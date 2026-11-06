// Publish a LONG-LIVED demo claim for the verifier page's one-click demo.
// Testnet only, demo wallet only. The claim stays VALID (never revoked):
// it is the live example a judge verifies in one click from verify.html.
//
//   node scripts/publish-demo-claim.mjs
//
// Flow: snapshot -> claims (30-day windows, so the Nov 6 demo transfers
// stay in-window past judging) -> REAL NEAR AI analysis via the stored
// custom.near-ai-veilproof credential (helper, never the key value) ->
// report (with the attested summary) -> tripwire -> publish hashes ->
// verify all 7 checks onchain -> write public/demo-report.json,
// public/demo-disclosure.json and public/demo-policy.json (the files the
// verifier page's demo button loads). Fail-closed at every step.
//
// Keys: reads ~/workspace/veilproof/.testnet-accounts.json (demo-prover
// only) to sign the publish call. Key material is NEVER printed, logged,
// or copied anywhere by this script. The AI helper swaps in the stored
// credential; this script never sees the key value.
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { connect, keyStores, KeyPair } from 'near-api-js';
import { fetchAccountSnapshot } from '../src/onchain.js';
import { evaluateClaims } from '../src/claims-engine.js';
import {
  sanitiseClaims,
  sanitiseMetrics,
  buildPromptMessages,
  parseModelOutput,
  checkClaimsConsistent,
} from '../src/ai-analysis.js';
import { canonicalJson } from '../src/canonical.js';
import { buildReport, reportHash, evidenceHash, policyHash } from '../src/report.js';
import { buildDisclosurePackage, assertPublicReportClean } from '../src/disclosure.js';
import { verifyReport } from '../src/verify-report.js';

const REGISTRY_ID = 'registry.veilproof.testnet';
const DEMO_ACCOUNT = 'veilproof-demo.testnet';
const POLICY_VERSION = 'veilproof-policy-v1';
// 30-day windows: the demo transfers (2026-11-06) stay in-window until
// ~2026-12-06, past judging (16-18 Nov). A 1-day window would make the
// claims fail on re-run a day later, so the demo claim would stop
// verifying. The report expires +30d, aligned with the windows.
const POLICY = {
  balanceAtLeastYocto: '5000000000000000000000000', // 5 NEAR
  minTxCount: 3,
  txWindowDays: 30,
  minVolumeYocto: '1000000000000000000000000', // 1 NEAR
  volumeWindowDays: 30,
  noFailedWindowDays: 30,
};
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

const accounts = JSON.parse(fs.readFileSync(ACCOUNTS_FILE, 'utf8'));
const demo = accounts['demo-prover'];
if (!demo || demo.accountId !== DEMO_ACCOUNT || typeof demo.privateKey !== 'string') {
  fail('demo-prover account missing in .testnet-accounts.json');
}
const history = JSON.parse(fs.readFileSync(HISTORY_FILE, 'utf8'));
if (history.accountId !== DEMO_ACCOUNT) fail('demo/history.json is not for the demo wallet');

console.log('[1/6] Fetch live snapshot');
const entries = history.transfers.map((t) => ({ hash: t.hash, senderId: t.senderId }));
const snapshot = await fetchAccountSnapshot(DEMO_ACCOUNT, entries);
if (snapshot.txs.length !== 4) fail(`expected 4 verified txs, got ${snapshot.txs.length}`);
if (!snapshot.txs.every((t) => t.status === 'Success')) fail('not all demo txs are Success');
console.log(`  PASS — 4/4 txs verified, balance ${fmtNear(snapshot.account.amount)} NEAR`);

console.log('[2/6] Evaluate claims (30-day windows)');
const nowNs = BigInt(Date.now()) * 1000000n;
const evaluation = evaluateClaims(snapshot, POLICY, nowNs);
for (const c of evaluation.claims) console.log(`  claim ${c.id}: passed=${c.passed} value=${c.value} threshold=${c.threshold}`);
if (!evaluation.allPassed) fail('not all claims passed — refusing to publish a failing demo report');
console.log('  PASS — all claims pass');

console.log('[3/6] Real NEAR AI analysis (stored VeilProof credential, via helper)');
const volumeClaim = evaluation.claims.find((c) => c.id === 'volume_in_window');
const claims = sanitiseClaims(evaluation.claims);
const metrics = sanitiseMetrics({
  balanceYocto: snapshot.account.amount,
  stakedYocto: snapshot.account.locked,
  txCount: snapshot.txs.length,
  successTxCount: snapshot.txs.filter((t) => t.status === 'Success').length,
  failedTxCount: snapshot.txs.filter((t) => t.status === 'Failure').length,
  volumeYocto: volumeClaim ? volumeClaim.value : '0',
  windowDays: 30,
  txWindowDays: 30,
  volumeWindowDays: 30,
  noFailedWindowDays: 30,
});
const messages = buildPromptMessages(claims, metrics, POLICY_VERSION);
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
const parsed = parseModelOutput(aiOut.output);
if (!parsed) fail('model output did not parse as a verdict');
const guard = checkClaimsConsistent(claims);
let { verdict, points } = parsed;
if (verdict === 'consistent' && !guard.consistent) {
  verdict = 'inconsistent';
  points = [...guard.problems.map((p) => `Deterministic check: ${p}`), ...points];
}
const attRef = createHash('sha256')
  .update(canonicalJson({ nonce, gateway: att.gateway_attestation, models: att.model_attestations }), 'utf8')
  .digest('hex');
const aiSummary = {
  provider: 'near-ai',
  model: 'z-ai/glm-5.3-flash',
  verdict,
  points,
  attestation: { verifiable: true, nonceMatched: true, ref: attRef },
};
console.log(`  PASS — verdict ${verdict}, ${points.length} points, attestation nonce echoed by ${gwEcho ? 'gateway' : ''}${gwEcho && mdlEcho ? ' + ' : ''}${mdlEcho ? 'model' : ''}, chat ${aiOut.chat_id}`);

console.log('[4/6] Build report + disclosure package + hashes');
const proverAddressHash = createHash('sha256').update(DEMO_ACCOUNT, 'utf8').digest('hex');
const expiresAt = computeExpiresAt(EXPIRY_DAYS);
const report = buildReport({
  proverAddressHash,
  claims: evaluation.claims,
  policyVersion: POLICY_VERSION,
  aiSummary,
  evidenceRefs: { dataHash: snapshot.dataHash, attestationRef: attRef },
  expiresAt,
});
assertPublicReportClean(report, DEMO_ACCOUNT, snapshot.txs.map((t) => t.hash));
const disclosurePackage = buildDisclosurePackage(report, DEMO_ACCOUNT, snapshot);
const hashes = {
  report_hash: reportHash(report),
  evidence_hash: evidenceHash(report.evidenceRefs),
  policy_hash: policyHash(report.policyVersion, POLICY),
};
console.log(`  PASS — reportId ${report.reportId} | expiresAt ${report.expiresAt} | AI verdict ${verdict}`);

console.log('[5/6] Publish hashes onchain (0.01 NEAR deposit, 100 TGas)');
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

console.log('[6/6] Verify the published claim (all 7 checks must pass)');
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
if (!result.valid) fail('verifyReport did not pass all 7 checks');
console.log('  PASS — all 7 checks pass on the published claim');

fs.writeFileSync(new URL('../public/demo-report.json', import.meta.url), JSON.stringify(report, null, 2) + '\n');
fs.writeFileSync(new URL('../public/demo-disclosure.json', import.meta.url), JSON.stringify(disclosurePackage, null, 2) + '\n');
fs.writeFileSync(new URL('../public/demo-policy.json', import.meta.url), JSON.stringify(POLICY, null, 2) + '\n');
console.log('\nDEMO CLAIM PUBLISHED (stays valid — never revoked by this script):');
console.log(JSON.stringify({ reportId: report.reportId, publishTxHash, aiVerdict: verdict, expiresAt: report.expiresAt }, null, 2));
