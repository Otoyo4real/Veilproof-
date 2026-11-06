// VeilProof demo — keyless, offline, from a fresh clone.
//
//   npm run demo
//
// Loads the committed public demo files (the live demo claim's report,
// disclosure package and policy), verifies all 9 checks locally against
// hashes computed from the report itself, then tampers with one claim
// value and shows the hash check failing. No wallet, no key, no network,
// no publish — this is the verifier proving it actually checks, on
// data anyone can read. The live onchain check is the same verifier
// run against the real registry record (see scripts/publish-demo-claim.mjs
// and the verify page's "Try the live demo claim" button).
import fs from 'node:fs';
import { verifyReport } from '../src/verify-report.js';
import { reportHash, evidenceHash, policyHash } from '../src/report.js';

const root = new URL('..', import.meta.url);
const read = (p) => JSON.parse(fs.readFileSync(new URL(p, root), 'utf8'));

const report = read('public/demo-report.json');
const disclosure = read('public/demo-disclosure.json');
const policy = read('public/demo-policy.json');

const nowNs = (BigInt(Date.now()) * 1000000n).toString();
// Local check: the "onchain record" here is recomputed from the report
// itself, so this proves internal consistency, not anchoring. The
// anchoring proof is the live check against registry.veilproof.testnet.
const localRecord = {
  report_hash: reportHash(report),
  evidence_hash: evidenceHash(report.evidenceRefs),
  policy_hash: policyHash(report.policyVersion, policy),
  valid: true,
};

console.log(`Demo claim ${report.reportId} — score ${report.score.value} (${report.score.band}, ${report.score.version})`);
console.log('Local verification (hashes recomputed from the report itself):');
const result = await verifyReport({ report, onchainRecord: localRecord, disclosurePackage: disclosure, policy, nowNs });
for (const c of result.checks) console.log(`  ${c.check}: ${c.passed ? 'PASS' : 'FAIL'} — ${c.detail}`);
console.log(result.valid ? 'PASS — all 9 checks pass locally' : 'FAIL — local verification did not pass');
if (!result.valid) process.exit(1);

// Tamper: change one claim value and show the verifier catching it.
const tampered = JSON.parse(JSON.stringify(report));
tampered.claims[0].value = '1';
const tamperedResult = await verifyReport({
  report: tampered,
  onchainRecord: localRecord,
  disclosurePackage: disclosure,
  policy,
  nowNs,
});
const failed = tamperedResult.checks.filter((c) => !c.passed).map((c) => c.check);
console.log(`\nTamper check (one claim value changed): ${failed.length > 0 ? `PASS — verifier caught it (${failed.join(', ')} failed)` : 'FAIL — tampered report passed!'}`);
if (failed.length === 0) process.exit(1);
