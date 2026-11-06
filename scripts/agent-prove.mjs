// VeilProof agent CLI — prove a treasury without the website.
//
// An agent (or a script acting for one) builds, verifies and
// optionally publishes a VeilProof report from the command line:
//
//   node scripts/agent-prove.mjs \
//     --keys keys.json \
//     --policy policy.json \
//     --txs txs.json \
//     [--sample-window 24] [--samples 4] \
//     [--underwrite|--no-underwrite] \
//     [--publish] \
//     [--out ./veilproof-out] \
//     [--site https://veilproof22.vercel.app]
//
// Keys file (JSON, chmod 600 — never commit it, never print it):
//   {
//     "primary": { "accountId": "agent.testnet", "privateKey": "ed25519:..." },
//     "linked": [
//       { "accountId": "treasury2.testnet", "privateKey": "ed25519:..." }
//     ],
//     "publisher": { "accountId": "publisher.veilproof.testnet", "privateKey": "ed25519:..." }
//   }
// "publisher" is only needed with --publish against a v2 registry
// (see src/registry.js): the dedicated publishing account signs the
// publish call, and is its own controller. Against the deployed v1
// registry the primary wallet signs and is recorded as owner. A v2
// publish without a publisher entry fails with a clear message.
// Linked wallets are proved by SIGNATURE (a NEP-413 link statement
// signed with the linked wallet's key): no transfer, no gas, no
// public onchain link between the wallets. The CLI signs the link
// itself from the keys file, verifies the signature, and confirms
// each public key against the chain's access key list.
//
// Txs file (JSON): either a plain array of { hash, senderId? } or an
// object with a `transfers` array (the demo/history.json shape).
// Entries whose sender is a linked wallet belong to that wallet's
// snapshot; the rest belong to the primary. A linked wallet needs no
// txs at all — its snapshot can be balance-only.
//
// Policy file (JSON): the claim thresholds (see
// examples/agent-policy.json). The policy is published by hash with
// the report, so the verifier re-runs the exact same rules.
//
// What the CLI sends where:
// - NEAR testnet RPC: read-only (account state, tx verification,
//   access key lists) + the publish call when --publish is given.
// - <site>/api/analyze (only with --underwrite): claim-level data
//   only (claims, metrics, score, policyVersion) — never an address,
//   snapshot or tx hash. The route returns the attested underwriting
//   summary, which the CLI attaches to the report. If the call fails,
//   the CLI warns and continues WITHOUT an AI summary (a report
//   without AI is still a valid, verifiable report).
// - Nothing else leaves this machine. Private keys are never printed,
//   logged or sent anywhere.
//
// Dry run (default): builds the report + disclosure and verifies them
// LOCALLY — the onchain record does not exist yet, so the report-hash
// checks compare against the locally computed hashes and the run is
// labelled a local check. --publish signs the publish call (0.01 NEAR
// deposit, 100 TGas) and then re-verifies against the REAL onchain
// record (get_claim + is_claim_valid).
//
// Exit code 0 on success, 1 on any failure. Private keys are never
// echoed, even on failure.
import fs from 'node:fs';
import path from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import nacl from 'tweetnacl';
import { connect, keyStores, KeyPair } from 'near-api-js';
import { fetchAccountSnapshot, dataHashForSnapshots } from '../src/onchain.js';
import { describeSampling } from '../src/sampling.js';
import { evaluateClaims } from '../src/claims-engine.js';
import { computeScore } from '../src/score.js';
import { sanitiseClaims, sanitiseMetrics } from '../src/ai-analysis.js';
import { canonicalJson } from '../src/canonical.js';
import { buildReport, reportHash, evidenceHash, policyHash, newProverSalt, commitAddress } from '../src/report.js';
import { buildMultiDisclosurePackage, assertPublicReportClean } from '../src/disclosure.js';
import { encryptDisclosurePackage, verifierKeyFingerprint } from '../src/crypto-box.js';
import { verifyReport } from '../src/verify-report.js';
import { base58Decode, base58Encode, signLinkMessage } from '../src/nep413.js';
// Registry v2 (commitments, allowlisted publisher): --publish probes
// the registry version and uses the v1 flow (primary signs, owner
// asserted) or the v2 flow (dedicated publisher signs, publisher
// commitment asserted). See docs/contract-migration.md.
import { probeContractVersion, isV2Version, buildV2PublishArgs } from '../src/registry.js';

const REGISTRY_ID = 'registry.veilproof.testnet';
const RPC_URL = 'https://rpc.testnet.near.org';
const DEFAULT_SITE = 'https://veilproof22.vercel.app';
const PUBLISH_DEPOSIT_YOCTO = 10n ** 22n; // 0.01 NEAR
const PUBLISH_GAS = 100_000_000_000_000n; // 100 TGas

function fail(msg) {
  throw new Error(`agent-prove: ${msg}`);
}
function fmtNear(yocto) {
  const v = BigInt(yocto);
  return (v / 10n ** 24n).toString() + '.' + (v % 10n ** 24n).toString().padStart(24, '0').slice(0, 4);
}
function computeExpiresAt(days) {
  const nowNs = BigInt(Date.now()) * 1000000n;
  const expires = nowNs + BigInt(days) * 86400n * 1000000000n;
  return (expires - (expires % 1000000000n)).toString();
}
// Aggregate metrics across the bundle, mirroring public/app.js
// buildMetrics: union txs deduped by hash, summed balances/staked.
function buildMetrics(snapshots, policy) {
  const ids = new Set(snapshots.map((s) => s.account.accountId));
  let balance = 0n;
  let staked = 0n;
  let success = 0;
  let failed = 0;
  let volume = 0n;
  const seen = new Set();
  for (const snap of snapshots) {
    balance += BigInt(snap.account.amount);
    staked += BigInt(snap.account.locked);
    for (const tx of snap.txs) {
      if (seen.has(tx.hash)) continue;
      seen.add(tx.hash);
      if (tx.status === 'Success') {
        success += 1;
        if (ids.has(tx.senderId) || ids.has(tx.receiverId)) volume += BigInt(tx.amountYocto);
      } else if (tx.status === 'Failure') {
        failed += 1;
      }
    }
  }
  return {
    balanceYocto: balance.toString(),
    stakedYocto: staked.toString(),
    txCount: seen.size,
    successTxCount: success,
    failedTxCount: failed,
    volumeYocto: volume.toString(),
    windowDays: policy.txWindowDays ?? policy.volumeWindowDays ?? policy.noFailedWindowDays ?? 30,
    txWindowDays: policy.txWindowDays,
    volumeWindowDays: policy.volumeWindowDays,
    noFailedWindowDays: policy.noFailedWindowDays,
  };
}
function parseArgs(argv) {
  const args = { sampleWindow: 0, samples: 4, underwrite: true, publish: false, out: './veilproof-out', site: DEFAULT_SITE, expiryDays: 30 };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    const take = (name) => {
      const v = argv[i + 1];
      if (v === undefined || v.startsWith('--')) fail(`--${name} needs a value`);
      i += 1;
      return v;
    };
    if (a === '--keys') args.keys = take('keys');
    else if (a === '--policy') args.policy = take('policy');
    else if (a === '--txs') args.txs = take('txs');
    else if (a === '--sample-window') args.sampleWindow = Number(take('sample-window'));
    else if (a === '--samples') args.samples = Number(take('samples'));
    else if (a === '--out') args.out = take('out');
    else if (a === '--site') args.site = take('site');
    else if (a === '--expiry-days') args.expiryDays = Number(take('expiry-days'));
    else if (a === '--verifier-key') args.verifierKey = take('verifier-key');
    else if (a === '--underwrite') args.underwrite = true;
    else if (a === '--no-underwrite') args.underwrite = false;
    else if (a === '--publish') args.publish = true;
    else if (a === '--help' || a === '-h') args.help = true;
    else fail(`unknown argument: ${a}`);
  }
  return args;
}
function usage() {
  return `Usage: node scripts/agent-prove.mjs --keys keys.json --policy policy.json [--txs txs.json] [options]

  --keys <file>        Keys JSON: { primary: { accountId, privateKey }, linked: [...] }
  --policy <file>      Policy JSON (claim thresholds; see examples/agent-policy.json)
  --txs <file>         Tx JSON: [{ hash, senderId? }] or { transfers: [...] } (optional)
  --sample-window <h>  Balance sampling window in hours, 0 = none (default 0)
  --samples <n>        Sample readings per wallet (default 4)
  --underwrite         Ask the live site for an attested underwriting summary (default on)
  --no-underwrite      Skip the underwriting call
  --publish            Publish the hashes onchain (0.01 NEAR deposit); default is a dry run
  --out <dir>          Output directory for report.json, disclosure.json, policy.json (default ./veilproof-out)
  --verifier-key <b64> Encrypt the disclosure package for one verifier (Curve25519 public key, base64 — see docs/verifier-bound-disclosure.md); writes disclosure-encrypted.json, expiring with the report
  --site <url>         Live site for underwriting (default ${DEFAULT_SITE})
  --expiry-days <n>    Report expiry in days (default 30)
  --help               Show this help`;
}
function readJson(file, label) {
  let raw;
  try {
    raw = fs.readFileSync(file, 'utf8');
  } catch {
    fail(`cannot read ${label} file: ${file}`);
  }
  try {
    return JSON.parse(raw);
  } catch {
    fail(`${label} file is not valid JSON: ${file}`);
  }
}
function secretKeyBytes(privateKey, label) {
  if (typeof privateKey !== 'string' || !privateKey.startsWith('ed25519:')) {
    fail(`${label} privateKey must be an ed25519: key`);
  }
  const bytes = base58Decode(privateKey.slice('ed25519:'.length));
  if (bytes.length !== 64) fail(`${label} privateKey must decode to 64 bytes`);
  return bytes;
}
function publicKeyOf(secretKey) {
  const kp = nacl.sign.keyPair.fromSecretKey(secretKey);
  return `ed25519:${base58Encode(kp.publicKey)}`;
}
async function fetchAccessKeys(accountId) {
  const res = await fetch(RPC_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 'agent-prove-access-keys',
      method: 'query',
      params: { request_type: 'view_access_key_list', account_id: accountId, finality: 'final' },
    }),
  });
  const json = await res.json();
  if (json.error) throw new Error(json.error.message || json.error.name || 'RPC error');
  return (json.result.keys || []).map((k) => k.public_key);
}
async function underwriteViaSite(site, claims, metrics, score, policyVersion) {
  const res = await fetch(`${site.replace(/\/$/, '')}/api/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ mode: 'underwriting', claims, metrics, score, policyVersion }),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const json = await res.json();
  if (json.status !== 'ok' || !json.summary) {
    throw new Error(`underwriting not available (status: ${json.status || 'unknown'}${json.error ? `, ${json.error}` : ''})`);
  }
  return json.summary;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log(usage());
    return;
  }
  if (!args.keys) fail('--keys is required');
  if (!args.policy) fail('--policy is required');
  if (!Number.isFinite(args.sampleWindow) || args.sampleWindow < 0) fail('--sample-window must be 0 or more');
  if (!Number.isInteger(args.samples) || args.samples < 2) fail('--samples must be an integer >= 2');
  if (!Number.isInteger(args.expiryDays) || args.expiryDays < 1) fail('--expiry-days must be an integer >= 1');

  const keys = readJson(args.keys, 'keys');
  if (!keys.primary || typeof keys.primary.accountId !== 'string' || typeof keys.primary.privateKey !== 'string') {
    fail('keys file must have primary: { accountId, privateKey }');
  }
  const linkedKeys = Array.isArray(keys.linked) ? keys.linked : [];
  for (const lk of linkedKeys) {
    if (typeof lk.accountId !== 'string' || typeof lk.privateKey !== 'string') fail('each linked key must have { accountId, privateKey }');
    if (lk.accountId === keys.primary.accountId) fail(`linked wallet ${lk.accountId} is the primary address — list it only once`);
  }
  // Warn (do not fail) when the keys file is world-readable: it holds
  // private keys, and a 644 default is easy to miss.
  try {
    const mode = fs.statSync(args.keys).mode & 0o777;
    if (mode & 0o044) console.log(`WARNING: keys file ${args.keys} is readable by others (mode ${mode.toString(8)}). Run: chmod 600 ${args.keys}`);
  } catch { /* stat failure is not fatal */ }

  const policy = readJson(args.policy, 'policy');
  if (!policy || typeof policy !== 'object' || Array.isArray(policy)) fail('policy must be a JSON object');
  const policyVersion = typeof policy.policyVersion === 'string' && policy.policyVersion.length > 0 ? policy.policyVersion : 'veilproof-policy-v2';
  if (policy.policyVersion) delete policy.policyVersion;

  let txEntries = [];
  if (args.txs) {
    const txsJson = readJson(args.txs, 'txs');
    txEntries = Array.isArray(txsJson) ? txsJson : Array.isArray(txsJson.transfers) ? txsJson.transfers : null;
    if (!txEntries) fail('txs file must be an array or an object with a transfers array');
    for (const e of txEntries) {
      if (!e || typeof e.hash !== 'string' || e.hash.length === 0) fail('each tx entry must have a hash');
    }
  }

  const primaryAccountId = keys.primary.accountId;
  const primarySecret = secretKeyBytes(keys.primary.privateKey, 'primary');
  const primaryPublicKey = publicKeyOf(primarySecret);

  // A tx entry belongs to a wallet when that wallet sent it, received
  // it, or the entry names no counterparty (a bare hash is assumed to
  // be the wallet's own). Incoming transfers count: the primary is
  // the receiver of the link transfer and of the deployer's funding
  // transfers, and those are part of its history.
  const entriesFor = (accountId) =>
    txEntries.filter((e) => (!e.senderId && !e.receiverId) || e.senderId === accountId || e.receiverId === accountId);

  console.log(`[1/6] Fetch live snapshots for ${primaryAccountId}${linkedKeys.length > 0 ? ` + ${linkedKeys.length} linked wallet(s)` : ''}`);
  const primaryEntries = entriesFor(primaryAccountId);
  // Balance sampling: try the requested window, then halve down to
  // 0.25h (a young account cannot be sampled over a window older
  // than itself). Linked wallets reuse the primary's exact sample
  // heights, or the sustained/time-weighted claims refuse to run.
  const windows = args.sampleWindow > 0 ? [args.sampleWindow] : [0];
  if (args.sampleWindow > 0) {
    let w = args.sampleWindow;
    while (w / 2 >= 0.25) {
      w /= 2;
      windows.push(w);
    }
  }
  let primary = null;
  let sampleWindowUsed = 0;
  let lastSampleError = null;
  for (const windowHours of windows) {
    try {
      primary = await fetchAccountSnapshot(
        primaryAccountId,
        primaryEntries,
        windowHours > 0 ? { balanceSamples: { windowHours, samples: args.samples } } : {},
      );
      sampleWindowUsed = windowHours;
      break;
    } catch (err) {
      lastSampleError = err;
      console.log(`  sample window ${windowHours}h failed: ${err.message} — trying a shorter window`);
    }
  }
  if (!primary) fail(`no sample window worked (last error: ${lastSampleError?.message})`);
  console.log(`  primary balance ${fmtNear(primary.account.amount)} NEAR, ${primary.txs.length}/${primaryEntries.length} txs verified${sampleWindowUsed > 0 ? `, sampled ${sampleWindowUsed}h x ${args.samples}` : ''}`);
  // The primary key must belong to the primary account — the publish
  // transaction would prove it, but in a dry run nothing signs, so
  // check the chain's access key list now and fail early on a
  // wrong-keys-file instead of building a report nobody owns.
  const primaryKeysOnChain = await fetchAccessKeys(primaryAccountId);
  if (!primaryKeysOnChain.includes(primaryPublicKey)) {
    fail(`primary wallet ${primaryAccountId}: its key is not among the account's access keys — check the keys file`);
  }

  const linkedSnapshots = [];
  const linkSignatures = {};
  const linkKeyBindings = {};
  for (const lk of linkedKeys) {
    const entries = entriesFor(lk.accountId);
    const opts =
      sampleWindowUsed > 0 && primary.balanceSamples
        ? { balanceSamples: { windowHours: sampleWindowUsed, samples: args.samples, heights: primary.balanceSamples.map((s) => s.blockHeight) } }
        : {};
    const snap = await fetchAccountSnapshot(lk.accountId, entries, opts);
    const secret = secretKeyBytes(lk.privateKey, `linked ${lk.accountId}`);
    const publicKey = publicKeyOf(secret);
    // Confirm the key against the chain's access key list (the same
    // binding the verifier will check) before signing anything.
    const keysOnChain = await fetchAccessKeys(lk.accountId);
    if (!keysOnChain.includes(publicKey)) {
      fail(`linked wallet ${lk.accountId}: its key is not among the account's access keys — check the keys file`);
    }
    const nonceB64 = randomBytes(32).toString('base64');
    const linkSignature = signLinkMessage(secret, lk.accountId, primaryAccountId, nonceB64);
    linkSignatures[lk.accountId] = linkSignature;
    linkKeyBindings[lk.accountId] = publicKey;
    linkedSnapshots.push(snap);
    console.log(`  linked ${lk.accountId}: balance ${fmtNear(snap.account.amount)} NEAR, ${snap.txs.length}/${entries.length} txs verified, link signed (no transfer)`);
  }
  const snapshots = [primary, ...linkedSnapshots];

  console.log('[2/6] Evaluate claims');
  const nowNs = BigInt(Date.now()) * 1000000n;
  const bundle = { wallets: snapshots };
  const evaluation = evaluateClaims(bundle, policy, nowNs);
  for (const c of evaluation.claims) console.log(`  claim ${c.id}: passed=${c.passed} value=${c.value} threshold=${c.threshold}`);
  if (!evaluation.allPassed) fail('not all claims passed — refusing to build a failing report (lower the thresholds or fix the data)');

  console.log('[3/6] Compute deterministic score');
  const score = computeScore(bundle, {
    txWindowDays: policy.txWindowDays,
    volumeWindowDays: policy.volumeWindowDays,
    noFailedWindowDays: policy.noFailedWindowDays,
  }, nowNs);
  console.log(`  score ${score.value}/1000 (${score.band})`);
  for (const c of score.components) console.log(`    ${c.id}: ${c.points}/${c.max} measured=${c.measured}`);

  let aiSummary = null;
  let attRef = null;
  if (args.underwrite) {
    console.log('[4/6] Underwriting via the live site (claim-level data only)');
    try {
      const claims = sanitiseClaims(evaluation.claims);
      const metrics = sanitiseMetrics(buildMetrics(snapshots, policy));
      aiSummary = await underwriteViaSite(args.site, claims, metrics, score, policyVersion);
      attRef = aiSummary?.attestation?.ref ?? null;
      console.log(`  verdict ${aiSummary.verdict}${aiSummary.suggestedLimitNear !== null && aiSummary.suggestedLimitNear !== undefined ? `, suggested limit ${aiSummary.suggestedLimitNear} NEAR` : ''}, confidence ${aiSummary.confidence}`);
    } catch (err) {
      console.log(`  WARNING: underwriting unavailable (${err.message}) — continuing WITHOUT an AI summary. The report stays valid; it is simply unanalysed.`);
    }
  } else {
    console.log('[4/6] Underwriting skipped (--no-underwrite)');
  }

  console.log('[5/6] Build report + disclosure package');
  // P2 unlinkability: a fresh random salt per report (and per linked
  // wallet). The salts travel only inside the disclosure package.
  const proverSalt = newProverSalt();
  const linkedSalts = linkedKeys.map(() => newProverSalt());
  const proverAddressHash = commitAddress(primaryAccountId, proverSalt);
  const linkedProverHashes = linkedKeys.map((lk, i) => commitAddress(lk.accountId, linkedSalts[i]));
  const expiresAt = computeExpiresAt(args.expiryDays);
  const multiDataHash = await dataHashForSnapshots(snapshots);
  // Sampling evidence: the bundle-level record the verifier
  // recomputes from the disclosed samples (10th check).
  const sampling = describeSampling(bundle);
  const report = buildReport({
    proverAddressHash,
    claims: evaluation.claims,
    policyVersion,
    aiSummary,
    evidenceRefs: { dataHash: multiDataHash, attestationRef: attRef },
    expiresAt,
    linkedProverHashes,
    score,
    sampling,
  });
  // Counterparty account ids are checked as extra secrets: labels
  // stay in the disclosure, never in the public report.
  const counterpartyAccounts = Array.isArray(score.counterpartyLabels) ? score.counterpartyLabels.map((l) => l.account) : [];
  assertPublicReportClean(report, primaryAccountId, primary.txs.map((t) => t.hash), [proverSalt, ...linkedSalts], counterpartyAccounts);
  for (let i = 0; i < linkedSnapshots.length; i += 1) {
    assertPublicReportClean(report, linkedKeys[i].accountId, linkedSnapshots[i].txs.map((t) => t.hash), [proverSalt, ...linkedSalts], counterpartyAccounts);
  }
  const disclosurePackage = buildMultiDisclosurePackage(
    report,
    primaryAccountId,
    primary,
    linkedKeys.map((lk, i) => ({ address: lk.accountId, snapshot: linkedSnapshots[i], linkSignature: linkSignatures[lk.accountId], salt: linkedSalts[i] })),
    proverSalt,
  );
  const hashes = {
    report_hash: reportHash(report),
    evidence_hash: evidenceHash(report.evidenceRefs),
    policy_hash: policyHash(report.policyVersion, policy),
  };
  console.log(`  reportId ${report.reportId} | expires ${new Date(Number(BigInt(expiresAt) / 1000000n)).toISOString()} | score ${score.value} (${score.band})`);

  let publishTxHash = null;
  let registryIsV2 = false;
  let expectedPublisherCommitment = null;
  if (args.publish) {
    console.log('[6/6] Publish hashes onchain (0.01 NEAR deposit, 100 TGas)');
    const keyStore = new keyStores.InMemoryKeyStore();
    await keyStore.setKey('testnet', primaryAccountId, KeyPair.fromString(keys.primary.privateKey));
    const near = await connect({
      networkId: 'testnet',
      nodeUrl: RPC_URL,
      walletUrl: 'https://testnet.mynearwallet.com/',
      helperUrl: 'https://helper.testnet.near.org',
      keyStore,
    });
    const account = await near.account(primaryAccountId);
    // Registry version probe: v1 has no get_version (null); v2
    // publishes from the dedicated publisher account in keys.publisher.
    const registryVersion = await probeContractVersion(
      (method, methodArgs) => account.viewFunction({ contractId: REGISTRY_ID, methodName: method, args: methodArgs }),
    );
    registryIsV2 = isV2Version(registryVersion);
    console.log(`  registry version: ${registryVersion ?? 'v1 (no get_version)'}`);
    let signerAccount = account;
    let publishArgs;
    if (registryIsV2) {
      const publisherEntry = keys.publisher;
      if (!publisherEntry || typeof publisherEntry.accountId !== 'string' || typeof publisherEntry.privateKey !== 'string') {
        fail('registry is v2 but no "publisher" entry in the keys file — add the dedicated publisher account (docs/contract-migration.md)');
      }
      await keyStore.setKey('testnet', publisherEntry.accountId, KeyPair.fromString(publisherEntry.privateKey));
      signerAccount = await near.account(publisherEntry.accountId);
      // The publisher is its own controller here; the treasury
      // (primary + linked wallets) is neither publisher nor controller.
      const built = buildV2PublishArgs({
        claimId: report.reportId,
        reportHash: hashes.report_hash,
        evidenceHash: hashes.evidence_hash,
        policyHash: hashes.policy_hash,
        expiresAt: Number(expiresAt),
        publisherAccountId: publisherEntry.accountId,
        controllerAccountId: publisherEntry.accountId,
      });
      publishArgs = built.args;
      expectedPublisherCommitment = built.commitments.publisher_commitment;
      console.log(`  v2 publish: signer ${publisherEntry.accountId} (dedicated publisher, controller itself)`);
    } else {
      publishArgs = {
        claim_id: report.reportId,
        report_hash: hashes.report_hash,
        evidence_hash: hashes.evidence_hash,
        policy_hash: hashes.policy_hash,
        expires_at: Number(expiresAt),
      };
      console.log(`  v1 publish: signer ${primaryAccountId} (primary wallet, recorded as owner)`);
    }
    const result = await signerAccount.functionCall({
      contractId: REGISTRY_ID,
      methodName: 'publish_claim',
      args: publishArgs,
      gas: PUBLISH_GAS,
      attachedDeposit: PUBLISH_DEPOSIT_YOCTO,
    });
    const receipts = (result && result.receipts) || [];
    for (const r of receipts) {
      if (r && r.receipt && r.receipt.id) publishTxHash = r.receipt.id;
    }
    if (!publishTxHash && result && result.transaction && result.transaction.hash) publishTxHash = result.transaction.hash;
    if (typeof publishTxHash !== 'string' || publishTxHash.length === 0) fail('publish returned no transaction hash');
    console.log(`  publish tx ${publishTxHash}`);
    console.log(`  explorer: https://testnet.nearblocks.io/txns/${publishTxHash}`);
  } else {
    console.log('[6/6] Dry run — not published (add --publish to put the hashes onchain)');
  }

  console.log(args.publish ? 'Verify the published claim against the REAL onchain record' : 'Local verification (the onchain record does not exist yet — this checks the report is internally consistent)');
  let onchainRecord;
  if (args.publish) {
    const keyStore = new keyStores.InMemoryKeyStore();
    await keyStore.setKey('testnet', primaryAccountId, KeyPair.fromString(keys.primary.privateKey));
    const near = await connect({
      networkId: 'testnet',
      nodeUrl: RPC_URL,
      walletUrl: 'https://testnet.mynearwallet.com/',
      helperUrl: 'https://helper.testnet.near.org',
      keyStore,
    });
    const account = await near.account(primaryAccountId);
    const claim = await account.viewFunction({ contractId: REGISTRY_ID, methodName: 'get_claim', args: { claim_id: report.reportId } });
    if (claim === null) fail('get_claim returned null right after publish');
    if (registryIsV2) {
      if ('owner' in claim) fail('v2 get_claim still returns an owner field');
      if (claim.publisher_commitment !== expectedPublisherCommitment) fail(`onchain publisher_commitment ${claim.publisher_commitment} does not match the expected commitment for the publisher account`);
    } else if (claim.owner !== primaryAccountId) fail(`onchain owner ${claim.owner} is not the primary wallet`);
    const valid = await account.viewFunction({ contractId: REGISTRY_ID, methodName: 'is_claim_valid', args: { claim_id: report.reportId } });
    onchainRecord = { report_hash: claim.report_hash, evidence_hash: claim.evidence_hash, policy_hash: claim.policy_hash, valid };
  } else {
    onchainRecord = { ...hashes, valid: true };
  }
  const result = verifyReport({
    report,
    onchainRecord,
    disclosurePackage,
    policy,
    nowNs: nowNs.toString(),
    linkKeyBindings,
  });
  for (const c of result.checks) console.log(`  check ${c.check}: ${c.passed ? 'PASS' : 'FAIL'} — ${c.detail}`);
  if (!result.valid) fail('verification did not pass all 10 checks');
  console.log(`  ${args.publish ? 'PASS — all 10 checks pass on the published claim' : 'PASS — all 10 checks pass locally (publish to make them verifiable by anyone)'}`);

  fs.mkdirSync(args.out, { recursive: true });
  fs.writeFileSync(path.join(args.out, 'report.json'), JSON.stringify(report, null, 2) + '\n');
  fs.writeFileSync(path.join(args.out, 'disclosure.json'), JSON.stringify(disclosurePackage, null, 2) + '\n');
  fs.writeFileSync(path.join(args.out, 'policy.json'), JSON.stringify(policy, null, 2) + '\n');
  console.log(`\nWrote ${path.join(args.out, 'report.json')}, disclosure.json, policy.json`);
  // P4 verifier-bound disclosure: encrypt the package for one verifier
  // (their Curve25519 public key, base64). The encrypted package
  // expires with the report; only that verifier can open it.
  if (args.verifierKey) {
    const encrypted = encryptDisclosurePackage(disclosurePackage, args.verifierKey, report.expiresAt);
    const encryptedPath = path.join(args.out, 'disclosure-encrypted.json');
    fs.writeFileSync(encryptedPath, JSON.stringify(encrypted, null, 2) + '\n');
    console.log(`Wrote ${encryptedPath} (verifier key fingerprint ${verifierKeyFingerprint(args.verifierKey).slice(0, 16)}…)`);
    console.log('  Only the holder of that verifier key can open it; it expires with the report.');
  }
  console.log(JSON.stringify({
    reportId: report.reportId,
    published: args.publish,
    publishTxHash,
    score: `${score.value} (${score.band})`,
    aiVerdict: aiSummary ? aiSummary.verdict : null,
    suggestedLimitNear: aiSummary ? aiSummary.suggestedLimitNear : null,
    sampleWindowHours: sampleWindowUsed,
    expiresAt: report.expiresAt,
  }, null, 2));
}

main().catch((err) => {
  console.error(err.message || String(err));
  process.exit(1);
});
