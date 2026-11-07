// VeilProof live demo claim integration test — pure, no network.
//
// Loads the committed demo files (report 2e8675fa662f06a4, disclosure,
// policy) and runs the real verifier against a local record recomputed
// from the report itself. This is the internal-consistency check; the
// anchoring proof (the same hashes on the real registry record) was
// verified live against registry.veilproof.testnet and is pinned here
// as the expected report hash.
//
// nowNs is the claim's onchain publish time (created_at), not the
// wall clock: the demo transactions live in the 30-day windows ending
// at publication, and the claim expires 2026-12-07, so a wall-clock
// now would age the demo out of its own windows.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { verifyReport } from '../src/verify-report.js';
import { reportHash, evidenceHash, policyHash } from '../src/report.js';

const root = new URL('..', import.meta.url);
const read = (p) => JSON.parse(readFileSync(new URL(p, root), 'utf8'));

const report = read('public/demo-report.json');
const disclosure = read('public/demo-disclosure.json');
const policy = read('public/demo-policy.json');

// The onchain record for 2e8675fa662f06a4, read live from
// registry.veilproof.testnet (get_claim) on 2026-11-07, after the v2
// migration. Published from the dedicated publisher
// publisher.veilproof.testnet (v2, no owner field).
const ONCHAIN_REPORT_HASH = '0edbbc297f67729acf9a91768941c83bca6ff29c672c433b154393001e4b7532';
const ONCHAIN_EVIDENCE_HASH = '72f07bb8dc83e8bb8d7fed5ec62aa1727a443db2ed5bdbcb06d3ca9a5e46eaca';
const ONCHAIN_POLICY_HASH = '3b77a1797fa0fdab89d3af974229ed98b00f11d35b0a0ced84f8aca064171437';
const PUBLISHED_AT_NS = '1794031991551539000';

const CHECK_ORDER = ['prover_binding', 'report_hash', 'evidence_hash', 'policy_hash', 'data_hash', 'sampling', 'claims', 'score', 'link_proofs', 'validity'];

test('demo claim: the committed files match the live onchain record', () => {
  assert.equal(report.reportId, '2e8675fa662f06a4');
  assert.equal(reportHash(report), ONCHAIN_REPORT_HASH);
  assert.equal(evidenceHash(report.evidenceRefs), ONCHAIN_EVIDENCE_HASH);
  assert.equal(policyHash(report.policyVersion, policy), ONCHAIN_POLICY_HASH);
  assert.equal(report.expiresAt, '1796623977000000000');
});

test('demo claim: all 10 checks pass, band solid, sampling complete with rpc timestamps', async () => {
  const localRecord = {
    report_hash: reportHash(report),
    evidence_hash: evidenceHash(report.evidenceRefs),
    policy_hash: policyHash(report.policyVersion, policy),
    valid: true,
  };
  const result = await verifyReport({
    report,
    onchainRecord: localRecord,
    disclosurePackage: disclosure,
    policy,
    nowNs: PUBLISHED_AT_NS,
  });
  assert.equal(result.valid, true);
  assert.deepEqual(result.checks.map((c) => c.check), CHECK_ORDER);
  assert.ok(result.checks.every((c) => c.passed), 'every check must pass');
  const sampling = result.checks.find((c) => c.check === 'sampling');
  assert.ok(sampling.detail.includes('4 reading(s)'));
  assert.ok(sampling.detail.includes('interval 900 blocks'));
  assert.ok(sampling.detail.includes('completeness complete'));
  const score = result.checks.find((c) => c.check === 'score');
  assert.ok(score.detail.includes('band solid'));
  assert.ok(score.detail.includes('Risk flags: 2'));
  assert.equal(result.score.band, 'solid');
  assert.equal(result.score.version, 'score-v2');
  assert.deepEqual(result.score.riskFlags.map((f) => f.type).sort(), ['concentrated_counterparty', 'internal_transfers']);
  assert.deepEqual(result.score.counterpartyLabels.map((l) => `${l.account}=${l.label}`).sort(), [
    'demo2.veilproof.testnet=own',
    'veilproof-demo.testnet=own',
    'veilproof.testnet=suspicious',
  ]);
  assert.equal(result.sampling.completeness, 'complete');
  assert.equal(result.sampling.sampleCount, 4);
  assert.equal(result.sampling.intervalBlocks, 900);
  assert.equal(result.sampling.timestampSource, 'rpc');
  assert.equal(result.sampling.lowestObservedSampledBalance, '12647562879201382200000000');
  assert.equal(result.sampling.wideIntervalWarning, null);
  // The public report carries the same sampling record and score
  // extras the verifier recomputed.
  assert.deepEqual(report.sampling, result.sampling);
  assert.deepEqual(report.score.riskFlags, result.score.riskFlags);
  assert.deepEqual(report.score.counterpartySummary, { own: 2, unknown: 0, suspicious: 1 });
  assert.ok(report.score.disclaimer.includes('not a guarantee of repayment'));
});

test('demo claim: the verifier still catches a tampered sampling record', async () => {
  const localRecord = {
    report_hash: reportHash(report),
    evidence_hash: evidenceHash(report.evidenceRefs),
    policy_hash: policyHash(report.policyVersion, policy),
    valid: true,
  };
  const tampered = JSON.parse(JSON.stringify(report));
  tampered.sampling.lowestObservedSampledBalance = '999000000000000000000000000';
  const result = await verifyReport({
    report: tampered,
    onchainRecord: localRecord,
    disclosurePackage: disclosure,
    policy,
    nowNs: PUBLISHED_AT_NS,
  });
  assert.equal(result.valid, false);
  assert.equal(result.checks.find((c) => c.check === 'sampling').passed, false);
});
