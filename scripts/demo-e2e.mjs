// VeilProof end-to-end demo loop — LOCAL, testnet only, demo wallets only.
//
// Runs the 13-step demo from README.md minus the browser/site parts
// (those wait on deployment) and minus the live AI step (the separate
// NEAR AI key does not exist yet — the AI step is recorded honestly as
// "not analysed", never faked).
//
//   node scripts/demo-e2e.mjs
//
// Flow: snapshot -> claims -> AI attempt (expect not_configured) ->
// report + tripwire + disclosure -> publish hashes onchain ->
// verify all 7 checks -> tamper must FAIL -> revoke -> verify must
// FAIL on validity. Any step failing stops the run with a clear error;
// nothing is ever reported as passing unless it actually passed.
//
// Keys: reads ~/workspace/veilproof/.testnet-accounts.json (demo-prover
// only) to sign the publish/revoke calls. Key material is NEVER printed,
// logged, or copied anywhere by this script.
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import { connect, keyStores, KeyPair } from 'near-api-js';
import { fetchAccountSnapshot } from '../src/onchain.js';
import { evaluateClaims } from '../src/claims-engine.js';
import { analyseClaims } from '../src/ai-analysis.js';
import { buildReport, reportHash, evidenceHash, policyHash } from '../src/report.js';
import { buildDisclosurePackage, assertPublicReportClean } from '../src/disclosure.js';
import { verifyReport } from '../src/verify-report.js';

const REGISTRY_ID = 'registry.veilproof.testnet';
const DEMO_ACCOUNT = 'veilproof-demo.testnet';
const POLICY_VERSION = 'veilproof-policy-v1';
// The same thresholds the claims engine was verified with.
const POLICY = {
  balanceAtLeastYocto: '5000000000000000000000000', // 5 NEAR
  minTxCount: 3,
  txWindowDays: 1,
  minVolumeYocto: '1000000000000000000000000', // 1 NEAR
  volumeWindowDays: 1,
  noFailedWindowDays: 1,
};
const EXPIRY_DAYS = 30;
// Mirror public/app.js exactly: 0.01 NEAR attached, 100 TGas limit.
// Storage is charged at cost (roughly 0.003-0.005 NEAR for a claim
// record) and the excess deposit is refunded; gas actually used is paid.
const PUBLISH_DEPOSIT_YOCTO = 10n ** 22n; // 0.01 NEAR
const PUBLISH_GAS = 100_000_000_000_000n; // 100 TGas
const REVOKE_GAS = 100_000_000_000_000n; // 100 TGas

const ACCOUNTS_FILE = new URL('../.testnet-accounts.json', import.meta.url);

// --- tiny harness: every step prints a pass/fail line; fail stops the run.
let stepNo = 0;
function step(label) {
  stepNo += 1;
  console.log(`\n[STEP ${stepNo}] ${label}`);
}
function ok(detail) {
  console.log(`  PASS — ${detail}`);
}
function info(detail) {
  console.log(`  ${detail}`);
}
function fail(message) {
  throw new Error(`STEP ${stepNo} FAILED: ${message}`);
}
function check(cond, message) {
  if (!cond) fail(message);
}

// Expiry rule: the contract's expires_at is a u64 nanosecond timestamp
// passed as a JSON number, so it must survive Number -> JSON string ->
// u64 exactly. public/app.js rounds to a multiple of 1024 ns, claiming
// that is exactly representable — that claim is WRONG at current
// timestamps (verified 2026-11-06: a 1024-aligned value's shortest
// decimal string does not round-trip, so computeExpiresAt there throws
// and the browser report build fails; the frontend needs the same fix
// as here). This script rounds DOWN to a whole second (multiple of
// 10^9 ns) instead: the value is exactly representable as a double AND
// its decimal string round-trips, so JSON.stringify sends the exact
// value the report carries and the onchain record agrees exactly.
function computeExpiresAt(days) {
  const nowNs = BigInt(Date.now()) * 1000000n;
  const expires = nowNs + BigInt(days) * 86400n * 1000000000n;
  const aligned = expires - (expires % 1000000000n);
  if (BigInt(Number(aligned).toString()) !== aligned) {
    throw new Error('expiry timestamp is not exactly representable as a JSON number — refusing to publish');
  }
  return aligned.toString();
}

function extractTxHash(result) {
  if (!result || typeof result !== 'object') return null;
  if (result.transaction && typeof result.transaction.hash === 'string') return result.transaction.hash;
  if (typeof result.transactionHash === 'string') return result.transactionHash;
  if (typeof result.hash === 'string') return result.hash;
  if (Array.isArray(result.transactionHashes) && result.transactionHashes[0]) return result.transactionHashes[0];
  return null;
}

function fmtNear(yocto) {
  const n = BigInt(yocto);
  const whole = n / 10n ** 24n;
  const frac = (n % 10n ** 24n).toString().padStart(24, '0').replace(/0+$/, '');
  return frac ? `${whole}.${frac}` : `${whole}`;
}

const results = {};

async function main() {
  // --- Setup: no AI key may be present; this demo records "not analysed".
  if (process.env.VEILPROOF_NEAR_AI_API_KEY) {
    fail('VEILPROOF_NEAR_AI_API_KEY is set in this environment — this demo expects no key (AI step is "not analysed"). Unset it and re-run.');
  }
  const accounts = JSON.parse(fs.readFileSync(ACCOUNTS_FILE, 'utf8'));
  const demo = accounts['demo-prover'];
  if (!demo || demo.accountId !== DEMO_ACCOUNT || typeof demo.privateKey !== 'string') {
    fail('demo-prover account missing or mismatched in .testnet-accounts.json');
  }
  const history = JSON.parse(fs.readFileSync(new URL('../demo/history.json', import.meta.url), 'utf8'));
  if (history.accountId !== DEMO_ACCOUNT) fail('demo/history.json is not for the demo wallet');

  // --- Step 1: live snapshot, verify the 4 demo txs.
  step('Fetch live snapshot for veilproof-demo.testnet (demo steps 3-4)');
  const entries = history.transfers.map((t) => ({ hash: t.hash, senderId: t.senderId }));
  const snapshot = await fetchAccountSnapshot(DEMO_ACCOUNT, entries);
  check(snapshot.txs.length === 4, `expected 4 verified txs, got ${snapshot.txs.length}`);
  check(snapshot.txs.every((t) => t.status === 'Success'), 'not all demo txs are Success');
  for (const t of snapshot.txs) {
    info(`tx ${t.hash.slice(0, 12)}… ${t.senderId} -> ${t.receiverId} ${fmtNear(t.amountYocto)} NEAR ${t.status} (block ${t.blockHeight})`);
  }
  info(`balance ${fmtNear(snapshot.account.amount)} NEAR | locked ${fmtNear(snapshot.account.locked)} NEAR | block ${snapshot.blockHeight}`);
  info(`dataHash ${snapshot.dataHash}`);
  ok('4/4 demo txs verified from the chain');

  // --- Step 2: evaluate claims.
  step('Evaluate claims under the demo policy (demo step 4)');
  const nowNs = BigInt(Date.now()) * 1000000n;
  const evaluation = evaluateClaims(snapshot, POLICY, nowNs);
  for (const c of evaluation.claims) {
    info(`claim ${c.id}: passed=${c.passed} value=${c.value} threshold=${c.threshold}`);
  }
  check(evaluation.allPassed, 'not all claims passed — refusing to publish a failing demo report');
  ok('all 4 claims pass');
  results.claims = evaluation.claims;

  // --- Step 3: AI analysis attempt — must be not_configured, never faked.
  step('Attempt NEAR AI analysis (demo steps 5-6) — expect not_configured');
  const volumeClaim = evaluation.claims.find((c) => c.id === 'volume_in_window');
  const metrics = {
    balanceYocto: snapshot.account.amount,
    stakedYocto: snapshot.account.locked,
    txCount: snapshot.txs.length,
    successTxCount: snapshot.txs.filter((t) => t.status === 'Success').length,
    failedTxCount: snapshot.txs.filter((t) => t.status === 'Failure').length,
    volumeYocto: volumeClaim ? volumeClaim.value : '0',
    windowDays: 1,
    txWindowDays: 1,
    volumeWindowDays: 1,
    noFailedWindowDays: 1,
  };
  const ai = await analyseClaims({ claims: evaluation.claims, metrics, policyVersion: POLICY_VERSION });
  check(ai.status === 'not_configured', `expected AI status 'not_configured', got '${ai.status}'`);
  check(ai.summary === null, 'AI summary must be null when not configured');
  ok('AI status not_configured — report will honestly say "not analysed" (no key yet)');

  // --- Step 4: build the report, tripwire, disclosure package, hashes.
  step('Build report + disclosure package + hashes (demo step 7)');
  const proverAddressHash = createHash('sha256').update(DEMO_ACCOUNT, 'utf8').digest('hex');
  const expiresAt = computeExpiresAt(EXPIRY_DAYS);
  const report = buildReport({
    proverAddressHash,
    claims: evaluation.claims,
    policyVersion: POLICY_VERSION,
    aiSummary: null,
    evidenceRefs: { dataHash: snapshot.dataHash, attestationRef: null },
    expiresAt,
  });
  check(report.aiSummary === null, 'report aiSummary must be null');
  assertPublicReportClean(report, DEMO_ACCOUNT, snapshot.txs.map((t) => t.hash));
  const disclosurePackage = buildDisclosurePackage(report, DEMO_ACCOUNT, snapshot);
  const hashes = {
    report_hash: reportHash(report),
    evidence_hash: evidenceHash(report.evidenceRefs),
    policy_hash: policyHash(report.policyVersion, POLICY),
  };
  info(`reportId ${report.reportId} | expiresAt ${report.expiresAt} (ns, +${EXPIRY_DAYS}d)`);
  info(`prover commitment ${report.prover}`);
  info(`report_hash ${hashes.report_hash}`);
  info(`evidence_hash ${hashes.evidence_hash}`);
  info(`policy_hash ${hashes.policy_hash}`);
  ok('report built; tripwire clean (no address, no tx hash in the public report)');
  results.report = report;
  results.hashes = hashes;

  // --- Step 5: publish the hashes onchain (signed, demo wallet).
  step('Publish hashes to registry.veilproof.testnet (demo step 8)');
  info(`cost preview: attached deposit 0.01 NEAR, gas limit 100 TGas; contract charges storage at cost (~0.003-0.005 NEAR) and refunds the excess; gas actually used is paid`);
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
  const balanceBefore = (await demoAccount.getAccountBalance()).available;
  info(`demo wallet balance before publish: ${fmtNear(balanceBefore)} NEAR`);
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
  check(typeof publishTxHash === 'string' && publishTxHash.length > 0, 'publish returned no transaction hash');
  info(`publish tx: ${publishTxHash}`);
  info(`explorer: https://testnet.nearblocks.io/txns/${publishTxHash}`);
  const balanceAfter = (await demoAccount.getAccountBalance()).available;
  info(`demo wallet balance after publish: ${fmtNear(balanceAfter)} NEAR (net cost ${fmtNear(BigInt(balanceBefore) - BigInt(balanceAfter))} NEAR incl. gas)`);
  ok(`publish_claim executed, tx ${publishTxHash}`);
  results.publishTxHash = publishTxHash;

  // --- Step 6: fetch the onchain record and verify all 7 checks.
  step('Fetch onchain record + verify the report (demo steps 9-11)');
  const claim = await demoAccount.viewFunction({
    contractId: REGISTRY_ID,
    methodName: 'get_claim',
    args: { claim_id: report.reportId },
  });
  check(claim !== null, 'get_claim returned null right after publish');
  check(claim.owner === DEMO_ACCOUNT, `onchain owner ${claim.owner} is not the demo wallet`);
  check(claim.report_hash === hashes.report_hash, 'onchain report_hash differs from the published hash');
  check(claim.evidence_hash === hashes.evidence_hash, 'onchain evidence_hash differs from the published hash');
  check(claim.policy_hash === hashes.policy_hash, 'onchain policy_hash differs from the published hash');
  check(claim.revoked === false, 'claim is revoked immediately after publish');
  const valid = await demoAccount.viewFunction({
    contractId: REGISTRY_ID,
    methodName: 'is_claim_valid',
    args: { claim_id: report.reportId },
  });
  check(valid === true, `is_claim_valid is ${valid}, expected true`);
  info(`onchain record: owner ${claim.owner} | revoked ${claim.revoked} | expires_at ${claim.expires_at}`);
  const verified = verifyReport({
    report,
    onchainRecord: { ...claim, valid },
    disclosurePackage,
    policy: POLICY,
    nowNs,
  });
  for (const c of verified.checks) {
    info(`check ${c.check}: ${c.passed ? 'PASS' : 'FAIL'} — ${c.detail}`);
  }
  check(verified.valid, 'verifyReport did not pass all 7 checks');
  check(verified.checks.length === 7, `expected 7 checks, got ${verified.checks.length}`);
  ok('all 7 verification checks pass; claim valid onchain');
  results.verifyChecks = verified.checks;
  results.onchainClaim = claim;

  // --- Step 7a: tampered report must FAIL verification.
  step('Negative check (a): tampered report must FAIL verification (demo step 12)');
  const tampered = JSON.parse(JSON.stringify(report));
  const balanceClaim = tampered.claims.find((c) => c.id === 'balance_at_least');
  check(balanceClaim, 'balance_at_least claim missing from the report — cannot tamper it');
  balanceClaim.value = '1'; // one yocto: contradicts the snapshot
  const tamperedResult = verifyReport({
    report: tampered,
    onchainRecord: { ...claim, valid },
    disclosurePackage,
    policy: POLICY,
    nowNs,
  });
  const tamperedHash = tamperedResult.checks.find((c) => c.check === 'report_hash');
  const tamperedClaims = tamperedResult.checks.find((c) => c.check === 'claims');
  check(tamperedResult.valid === false, 'CRITICAL: tampered report verified as valid');
  check(tamperedHash && tamperedHash.passed === false, 'tampered report_hash check did not fail');
  check(tamperedClaims && tamperedClaims.passed === false, 'tampered claims check did not fail');
  info(`tampered report_hash check: FAIL (as expected) — ${tamperedHash.detail}`);
  info(`tampered claims check: FAIL (as expected) — ${tamperedClaims.detail}`);
  ok('tampered report rejected by verification');
  results.tamper = { valid: tamperedResult.valid, failedChecks: tamperedResult.checks.filter((c) => !c.passed).map((c) => c.check) };

  // --- Step 7b: revoke the claim; verification must then FAIL on validity.
  step('Negative check (b): revoke the claim, then verification must fail (demo step 13)');
  const revokeResult = await demoAccount.functionCall({
    contractId: REGISTRY_ID,
    methodName: 'revoke_claim',
    args: { claim_id: report.reportId },
    gas: REVOKE_GAS,
    attachedDeposit: 0n,
  });
  const revokeTxHash = extractTxHash(revokeResult);
  check(typeof revokeTxHash === 'string' && revokeTxHash.length > 0, 'revoke returned no transaction hash');
  info(`revoke tx: ${revokeTxHash}`);
  const claimAfterRevoke = await demoAccount.viewFunction({
    contractId: REGISTRY_ID,
    methodName: 'get_claim',
    args: { claim_id: report.reportId },
  });
  check(claimAfterRevoke !== null && claimAfterRevoke.revoked === true, 'get_claim does not show revoked=true after revoke');
  const validAfterRevoke = await demoAccount.viewFunction({
    contractId: REGISTRY_ID,
    methodName: 'is_claim_valid',
    args: { claim_id: report.reportId },
  });
  check(validAfterRevoke === false, `is_claim_valid is ${validAfterRevoke} after revoke, expected false`);
  const revokedResult = verifyReport({
    report,
    onchainRecord: { ...claimAfterRevoke, valid: validAfterRevoke },
    disclosurePackage,
    policy: POLICY,
    nowNs,
  });
  const validityCheck = revokedResult.checks.find((c) => c.check === 'validity');
  check(revokedResult.valid === false, 'CRITICAL: revoked report verified as valid');
  check(validityCheck && validityCheck.passed === false, 'revoked validity check did not fail');
  info(`revoked validity check: FAIL (as expected) — ${validityCheck.detail}`);
  ok('revoked claim rejected by verification');
  results.revokeTxHash = revokeTxHash;
  results.revokedVerify = revokedResult.checks;

  // --- Step 8: final summary.
  step('Summary');
  console.log(JSON.stringify({
    reportId: report.reportId,
    publishTxHash,
    revokeTxHash,
    registry: REGISTRY_ID,
    owner: claim.owner,
    onchainRecord: claimAfterRevoke,
    hashes,
    verifyChecks: verified.checks.map((c) => ({ check: c.check, passed: c.passed })),
    tamper: results.tamper,
    revokedVerifyChecks: revokedResult.checks.map((c) => ({ check: c.check, passed: c.passed })),
    aiStatus: 'not_configured (no key — report honestly "not analysed")',
    explorer: `https://testnet.nearblocks.io/txns/${publishTxHash}`,
  }, null, 2));
  console.log('\nDEMO E2E: ALL STEPS PASSED');
}

main().catch((err) => {
  console.error(`\nDEMO E2E: FAILED at step ${stepNo}: ${err.message}`);
  process.exit(1);
});
