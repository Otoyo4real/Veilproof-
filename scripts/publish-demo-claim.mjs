// Publish a LONG-LIVED multi-wallet demo claim for the verifier page's
// one-click demo. Testnet only, demo wallets only. The claim stays VALID
// (never revoked): it is the live example a judge verifies in one click
// from verify.html. It SUPERSEDES the old single-wallet demo claim
// 86f237c0cf2e3fe6 (which stays valid onchain, just no longer the
// one-click demo).
//
//   node scripts/publish-demo-claim.mjs
//
// Flow: snapshots (primary + linked wallet, balance sampled at past
// block heights) -> claims under policy v2 (aggregate + sustained +
// time-weighted) -> deterministic score-v2 -> REAL NEAR AI underwriting
// via the stored custom.near-ai-veilproof credential (helper, never
// the key value) -> report (with score + attested underwriting summary)
// -> tripwire -> publish hashes -> verify all 9 checks onchain ->
// write public/demo-report.json, public/demo-disclosure.json and
// public/demo-policy.json (the files the verifier page's demo button
// loads). Fail-closed at every step.
//
// The linked wallet demo2.veilproof.testnet was created by
// scripts/setup-demo-linked-wallet.mjs; its link transfer to the
// primary wallet (0.5 NEAR) is the ownership proof. The balance
// sampling window falls back (1h -> 0.5h -> 0.25h) because the linked
// wallet is young: all 4 sample heights must postdate its creation.
//
// Keys: reads ~/workspace/veilproof/.testnet-accounts.json (demo-prover
// only) to sign the publish call. Key material is NEVER printed, logged,
// or copied anywhere by this script. The AI helper swaps in the stored
// credential; this script never sees the key value.
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { connect, keyStores, KeyPair } from 'near-api-js';
import { fetchAccountSnapshot, dataHashForSnapshots } from '../src/onchain.js';
import { evaluateClaims } from '../src/claims-engine.js';
import { computeScore } from '../src/score.js';
import {
  sanitiseClaims,
  sanitiseMetrics,
  buildUnderwritingPromptMessages,
  parseUnderwritingOutput,
  applyUnderwritingGuard,
} from '../src/ai-analysis.js';
import { canonicalJson } from '../src/canonical.js';
import { buildReport, reportHash, evidenceHash, policyHash } from '../src/report.js';
import { buildMultiDisclosurePackage, assertPublicReportClean } from '../src/disclosure.js';
import { verifyReport } from '../src/verify-report.js';

const REGISTRY_ID = 'registry.veilproof.testnet';
const DEMO_ACCOUNT = 'veilproof-demo.testnet';
const LINKED_ACCOUNT = 'demo2.veilproof.testnet';
// Link transfer sent by scripts/setup-demo-linked-wallet.mjs (0.5 NEAR
// from the linked wallet to the primary wallet): the ownership proof.
const LINK_TX_HASH = 'DNYq6teYhtgPfoBijzkNLENHuAatFzX5BNfZd1366DaN';
const POLICY_VERSION = 'veilproof-policy-v2';
// 30-day windows: the demo transfers (2026-11-06) stay in-window until
// ~2026-12-06, past judging (16-18 Nov). A 1-day window would make the
// claims fail on re-run a day later, so the demo claim would stop
// verifying. The report expires +30d, aligned with the windows.
// Thresholds are set against the real balances at publish time:
// primary ~10.6 NEAR, linked ~1.5 NEAR, aggregate ~12.1 NEAR.
const POLICY = {
  balanceAtLeastYocto: '5000000000000000000000000', // 5 NEAR
  minTxCount: 3,
  txWindowDays: 30,
  minVolumeYocto: '1000000000000000000000000', // 1 NEAR
  volumeWindowDays: 30,
  noFailedWindowDays: 30,
  aggregateBalanceAtLeastYocto: '10000000000000000000000000', // 10 NEAR
  aggregateMinTxCount: 5,
  aggregateTxWindowDays: 30,
  aggregateMinVolumeYocto: '2000000000000000000000000', // 2 NEAR
  aggregateVolumeWindowDays: 30,
  sustainedBalanceAtLeastYocto: '10000000000000000000000000', // 10 NEAR
  timeWeightedBalanceAtLeastYocto: '10000000000000000000000000', // 10 NEAR
};
const SAMPLE_WINDOWS_HOURS = [1, 0.5, 0.25]; // fallback: linked wallet is young
const SAMPLE_COUNT = 4;
const EXPIRY_DAYS = 30;
const PUBLISH_DEPOSIT_YOCTO = 10n ** 22n; // 0.01 NEAR
const PUBLISH_GAS = 100_000_000_000_000n; // 100 TGas
const AI_HELPER = new URL(
  '../../custom-connectors/custom.near-ai-veilproof/bin/near-ai-veilproof-call.py',
  import.meta.url,
).pathname;
const ACCOUNTS_FILE = new URL('../.testnet-accounts.json', import.meta.url);
const HISTORY_FILE = new URL('../demo/history.json', import.meta.url);

function fail(msg) {
  throw new Error(`publish-demo-claim: ${msg}`);
}
function fmtNear(yocto) {
  return (BigInt(yocto) / 10n ** 24n).toString() + '.' + (BigInt(yocto) % 10n ** 24n).toString().padStart(24, '0').slice(0, 4);
}
// Whole-second alignment, mirroring public/app.js: exactly representable
// as a double and as a JSON string at current timestamps.
function computeExpiresAt(days) {
  const nowNs = BigInt(Date.now()) * 1000000n;
  const expires = nowNs + BigInt(days) * 86400n * 1000000000n;
  return (expires - (expires % 1000000000n)).toString();
}
function extractTxHash(result) {
  const receipts = (result && result.receipts) || [];
  for (const r of receipts) {
    if (r && r.receipt && r.receipt.id) return r.receipt.id;
  }
  if (result && result.transaction && result.transaction.hash) return result.transaction.hash;
  return null;
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

const accounts = JSON.parse(fs.readFileSync(ACCOUNTS_FILE, 'utf8'));
const demo = accounts['demo-prover'];
if (!demo || demo.accountId !== DEMO_ACCOUNT || typeof demo.privateKey !== 'string') {
  fail('demo-prover account missing in .testnet-accounts.json');
}
const history = JSON.parse(fs.readFileSync(HISTORY_FILE, 'utf8'));
if (history.accountId !== DEMO_ACCOUNT) fail('demo/history.json is not for the demo wallet');

console.log('[1/7] Fetch live snapshots (primary + linked, with balance sampling)');
const entries = history.transfers.map((t) => ({ hash: t.hash, senderId: t.senderId }));
let primary = null;
let linked = null;
let sampleWindowUsed = null;
let lastSampleError = null;
for (const windowHours of SAMPLE_WINDOWS_HOURS) {
  try {
    primary = await fetchAccountSnapshot(DEMO_ACCOUNT, entries, { balanceSamples: { windowHours, samples: SAMPLE_COUNT } });
    // The linked wallet reuses the PRIMARY's exact sample heights:
    // the sustained/time-weighted claims refuse to run when wallets
    // were sampled at different heights, and two sequential "current
    // height" reads drift apart by a block.
    const heights = primary.balanceSamples.map((s) => s.blockHeight);
    linked = await fetchAccountSnapshot(LINKED_ACCOUNT, [{ hash: LINK_TX_HASH, senderId: LINKED_ACCOUNT }], { balanceSamples: { windowHours, samples: SAMPLE_COUNT, heights } });
    sampleWindowUsed = windowHours;
    break;
  } catch (err) {
    lastSampleError = err;
    console.log(`  sample window ${windowHours}h failed: ${err.message} — trying shorter window`);
  }
}
if (!primary || !linked) fail(`no sample window worked (last error: ${lastSampleError?.message})`);
if (primary.txs.length !== 5) fail(`expected 5 verified primary txs, got ${primary.txs.length}`);
if (!primary.txs.every((t) => t.status === 'Success')) fail('not all primary demo txs are Success');
if (linked.txs.length !== 1) fail(`expected 1 verified linked tx, got ${linked.txs.length}`);
const linkTx = linked.txs[0];
if (linkTx.status !== 'Success' || linkTx.senderId !== LINKED_ACCOUNT || linkTx.receiverId !== DEMO_ACCOUNT) {
  fail('link transfer is not a Success transfer from the linked wallet to the primary wallet');
}
console.log(`  PASS — primary 5/5 txs, balance ${fmtNear(primary.account.amount)} NEAR; linked 1/1 (link tx), balance ${fmtNear(linked.account.amount)} NEAR; sample window ${sampleWindowUsed}h x ${SAMPLE_COUNT}`);

console.log('[2/7] Evaluate claims under policy v2 (aggregate + sustained + time-weighted)');
const nowNs = BigInt(Date.now()) * 1000000n;
const bundle = { wallets: [primary, linked] };
const evaluation = evaluateClaims(bundle, POLICY, nowNs);
for (const c of evaluation.claims) console.log(`  claim ${c.id}: passed=${c.passed} value=${c.value} threshold=${c.threshold}`);
if (!evaluation.allPassed) fail('not all claims passed — refusing to publish a failing demo report');
console.log('  PASS — all claims pass');

console.log('[3/7] Compute deterministic score-v2');
const score = computeScore(bundle, {
  txWindowDays: POLICY.txWindowDays,
  volumeWindowDays: POLICY.volumeWindowDays,
  noFailedWindowDays: POLICY.noFailedWindowDays,
}, nowNs);
console.log(`  score ${score.value}/1000 (${score.band})`);
for (const c of score.components) console.log(`    ${c.id}: ${c.points}/${c.max} measured=${c.measured}`);

console.log('[4/7] Real NEAR AI underwriting (stored VeilProof credential, via helper)');
const claims = sanitiseClaims(evaluation.claims);
const metrics = sanitiseMetrics(buildMetrics([primary, linked], POLICY));
const messages = buildUnderwritingPromptMessages(claims, metrics, score, POLICY_VERSION);
let aiOut;
try {
  const raw = execFileSync(
    'python3',
    [AI_HELPER, 'complete'],
    { input: JSON.stringify({ model: 'z-ai/glm-5.3-flash', messages, max_tokens: 4000, temperature: 0.3 }), encoding: 'utf8', timeout: 180000 },
  );
  aiOut = JSON.parse(raw);
} catch (err) {
  fail(`AI helper call failed: ${err.message}`);
}
if (!aiOut || aiOut.verifiable !== true || !aiOut.attestation) fail('AI completion was not verifiable or had no attestation');
const att = aiOut.attestation;
const nonce = att.nonce;
const gwEcho = (att.gateway_attestation || {}).request_nonce === nonce;
const mdlEcho = ((att.model_attestations || [])[0] || {}).request_nonce === nonce;
if (!gwEcho && !mdlEcho) fail('attestation nonce did not echo — refusing to attach unattested evidence');
const parsed = parseUnderwritingOutput(aiOut.output);
if (!parsed) fail('model output did not parse as an underwriting verdict');
const guarded = applyUnderwritingGuard(parsed, score, evaluation.claims);
const attRef = createHash('sha256')
  .update(canonicalJson({ nonce, gateway: att.gateway_attestation, models: att.model_attestations }), 'utf8')
  .digest('hex');
const aiSummary = {
  provider: 'near-ai',
  model: 'z-ai/glm-5.3-flash',
  role: 'underwriting',
  verdict: guarded.verdict,
  suggestedLimitNear: guarded.suggestedLimitNear,
  confidence: guarded.confidence,
  points: guarded.points,
  attestation: { verifiable: true, nonceMatched: true, ref: attRef },
};
console.log(`  PASS — verdict ${guarded.verdict}${guarded.suggestedLimitNear !== null ? `, suggested limit ${guarded.suggestedLimitNear} NEAR` : ''}, confidence ${guarded.confidence}, ${guarded.points.length} points, attestation nonce echoed by ${gwEcho ? 'gateway' : ''}${gwEcho && mdlEcho ? ' + ' : ''}${mdlEcho ? 'model' : ''}, chat ${aiOut.chat_id}`);

console.log('[5/7] Build report + multi disclosure package + hashes');
const proverAddressHash = createHash('sha256').update(DEMO_ACCOUNT, 'utf8').digest('hex');
const linkedProverHashes = [createHash('sha256').update(LINKED_ACCOUNT, 'utf8').digest('hex')];
const expiresAt = computeExpiresAt(EXPIRY_DAYS);
// The evidence data hash is the MULTI hash over ALL snapshots (primary +
// linked), not the primary's single-wallet hash — mirroring app.js.
const multiDataHash = await dataHashForSnapshots([primary, linked]);
const report = buildReport({
  proverAddressHash,
  claims: evaluation.claims,
  policyVersion: POLICY_VERSION,
  aiSummary,
  evidenceRefs: { dataHash: multiDataHash, attestationRef: attRef },
  expiresAt,
  linkedProverHashes,
  score,
});
assertPublicReportClean(report, DEMO_ACCOUNT, primary.txs.map((t) => t.hash));
assertPublicReportClean(report, LINKED_ACCOUNT, linked.txs.map((t) => t.hash));
const disclosurePackage = buildMultiDisclosurePackage(report, DEMO_ACCOUNT, primary, [
  { address: LINKED_ACCOUNT, snapshot: linked, linkTxHash: LINK_TX_HASH },
]);
const hashes = {
  report_hash: reportHash(report),
  evidence_hash: evidenceHash(report.evidenceRefs),
  policy_hash: policyHash(report.policyVersion, POLICY),
};
console.log(`  PASS — reportId ${report.reportId} | expiresAt ${report.expiresAt} | score ${score.value} (${score.band}) | AI verdict ${guarded.verdict}`);

console.log('[6/7] Publish hashes onchain (0.01 NEAR deposit, 100 TGas)');
const keyStore = new keyStores.InMemoryKeyStore();
await keyStore.setKey('testnet', DEMO_ACCOUNT, KeyPair.fromString(demo.privateKey));
const near = await connect({
  networkId: 'testnet',
  nodeUrl: 'https://rpc.testnet.near.org',
  walletUrl: 'https://testnet.mynearwallet.com/',
  helperUrl: 'https://helper.testnet.near.org',
  keyStore,
});
const demoAccount = await near.account(DEMO_ACCOUNT);
const publishResult = await demoAccount.functionCall({
  contractId: REGISTRY_ID,
  methodName: 'publish_claim',
  args: {
    claim_id: report.reportId,
    report_hash: hashes.report_hash,
    evidence_hash: hashes.evidence_hash,
    policy_hash: hashes.policy_hash,
    expires_at: Number(expiresAt),
  },
  gas: PUBLISH_GAS,
  attachedDeposit: PUBLISH_DEPOSIT_YOCTO,
});
const publishTxHash = extractTxHash(publishResult);
if (typeof publishTxHash !== 'string' || publishTxHash.length === 0) fail('publish returned no transaction hash');
console.log(`  PASS — publish tx ${publishTxHash}`);
console.log(`  explorer: https://testnet.nearblocks.io/txns/${publishTxHash}`);

console.log('[7/7] Verify the published claim (all 9 checks must pass)');
const claim = await demoAccount.viewFunction({
  contractId: REGISTRY_ID,
  methodName: 'get_claim',
  args: { claim_id: report.reportId },
});
if (claim === null) fail('get_claim returned null right after publish');
if (claim.owner !== DEMO_ACCOUNT) fail(`onchain owner ${claim.owner} is not the demo wallet`);
const valid = await demoAccount.viewFunction({
  contractId: REGISTRY_ID,
  methodName: 'is_claim_valid',
  args: { claim_id: report.reportId },
});
if (valid !== true) fail(`is_claim_valid is ${valid}, expected true`);
const result = await verifyReport({
  report,
  onchainRecord: { report_hash: claim.report_hash, evidence_hash: claim.evidence_hash, policy_hash: claim.policy_hash, valid },
  disclosurePackage,
  policy: POLICY,
  nowNs: nowNs.toString(),
});
for (const c of result.checks) console.log(`  check ${c.check}: ${c.passed ? 'PASS' : 'FAIL'} — ${c.detail}`);
if (!result.valid) fail('verifyReport did not pass all 9 checks');
console.log('  PASS — all 9 checks pass on the published claim');

fs.writeFileSync(new URL('../public/demo-report.json', import.meta.url), JSON.stringify(report, null, 2) + '\n');
fs.writeFileSync(new URL('../public/demo-disclosure.json', import.meta.url), JSON.stringify(disclosurePackage, null, 2) + '\n');
fs.writeFileSync(new URL('../public/demo-policy.json', import.meta.url), JSON.stringify(POLICY, null, 2) + '\n');
console.log('\nDEMO CLAIM PUBLISHED (stays valid — never revoked by this script):');
console.log(JSON.stringify({ reportId: report.reportId, publishTxHash, score: `${score.value} (${score.band})`, aiVerdict: guarded.verdict, suggestedLimitNear: guarded.suggestedLimitNear, sampleWindowHours: sampleWindowUsed, expiresAt: report.expiresAt }, null, 2));
