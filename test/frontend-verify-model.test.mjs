// VeilProof honest verification model — frontend tests.
//
// The five status fields and the verifier panels, checked against the
// actual verifier output. No hardcoded VERIFIED: every status asserted
// here is produced by verifyReport from a fixture built in this file,
// or from the live demo claim files. The demo claim expectations below
// (band solid, privacy PRIVATE, attestation UNVERIFIED) are the
// published claim's own values, checked against a fresh recomputation.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';
import { evaluateClaims } from '../src/claims-engine.js';
import { computeScore } from '../src/score.js';
import { describeSampling } from '../src/sampling.js';
import { dataHashForSnapshots } from '../src/onchain.js';
import { buildReport, reportHash, evidenceHash, policyHash, newProverSalt, saltedAddressHash } from '../src/report.js';
import { buildDisclosurePackage } from '../src/disclosure.js';
import { verifyReport, summariseVerification } from '../src/verify-report.js';
import {
  verifyReport as verifyReportBrowser,
  summariseVerification as summariseBrowser,
  buildStatusPanelsHtml as buildPanelsBrowser,
} from '../public/js/verify-browser.js';

const ADDRESS = 'alice.veilproof.testnet';
const NOW_NS = 1793961600000000000n;
const DAY_NS = 86400n * 1_000_000_000n;
const EXPIRES_AT = (NOW_NS + 365n * DAY_NS).toString();
const POLICY_VERSION = 'veilproof-policy-v1';
const POLICY = {
  balanceAtLeastYocto: '1000000000000000000000000',
  stakedAtLeastYocto: '1000000000000000000000000',
  minTxCount: 1,
  txWindowDays: 30,
  minVolumeYocto: '1000000000000000000000000',
  volumeWindowDays: 30,
  noFailedWindowDays: 30,
};

function sha256Hex(s) {
  return createHash('sha256').update(s, 'utf8').digest('hex');
}

function tx(overrides = {}) {
  return {
    hash: 'A'.repeat(43),
    senderId: ADDRESS,
    receiverId: 'bob.veilproof.testnet',
    amountYocto: '1000000000000000000000000',
    status: 'Success',
    blockHeight: 100,
    blockTimestampNs: (NOW_NS - 10n * DAY_NS).toString(),
    ...overrides,
  };
}

function snapshot(overrides = {}) {
  const base = {
    account: {
      accountId: ADDRESS,
      amount: '5000000000000000000000000',
      locked: '2000000000000000000000000',
      storage_usage: 1000,
      blockHeight: 100,
    },
    txs: [
      tx({ hash: 'A'.repeat(43) }),
      tx({
        hash: 'B'.repeat(43),
        senderId: 'carol.veilproof.testnet',
        receiverId: ADDRESS,
        amountYocto: '500000000000000000000000',
        blockTimestampNs: (NOW_NS - 5n * DAY_NS).toString(),
      }),
    ],
    blockHeight: 100,
  };
  const snap = { ...base, ...overrides };
  snap.dataHash = dataHashForSnapshots([snap]);
  return snap;
}

function onchainRecordFor(report, { valid = true } = {}) {
  return {
    report_hash: reportHash(report),
    evidence_hash: evidenceHash(report.evidenceRefs),
    policy_hash: policyHash(POLICY_VERSION, POLICY),
    valid,
  };
}

// A scored, salted, predicate report over a snapshot that carries four
// balance samples 900 blocks apart. The salt keeps the report private;
// the score travels as a band only.
function scoredSalted(snap, { aiSummary = null, expiresAt = EXPIRES_AT } = {}) {
  const salt = newProverSalt();
  const { claims } = evaluateClaims(snap, POLICY, NOW_NS);
  const score = computeScore(snap, { txWindowDays: 30, volumeWindowDays: 30, noFailedWindowDays: 30 }, NOW_NS);
  const report = buildReport({
    proverAddressHash: saltedAddressHash(salt, ADDRESS),
    claims,
    policyVersion: POLICY_VERSION,
    aiSummary,
    evidenceRefs: { dataHash: snap.dataHash, attestationRef: null },
    expiresAt,
    score,
  });
  return {
    snapshot: snap,
    report,
    onchainRecord: onchainRecordFor(report),
    disclosurePackage: buildDisclosurePackage(report, ADDRESS, snap, salt),
    policy: POLICY,
    nowNs: NOW_NS,
  };
}

function sampledSnapshot() {
  const snap = snapshot();
  snap.balanceSamples = [100, 1000, 1900, 2800].map((blockHeight) => ({
    blockHeight,
    amount: '5000000000000000000000000',
  }));
  // A snapshot carrying samples hashes with the multi-wallet form
  // (dataHashForSnapshots), not the single-wallet form: the verifier
  // recomputes the same way, so the fixture must hash the same way.
  snap.dataHash = dataHashForSnapshots([snap]);
  return snap;
}

function fewSampleSnapshot() {
  const snap = snapshot();
  snap.balanceSamples = [100, 1000].map((blockHeight) => ({
    blockHeight,
    amount: '5000000000000000000000000',
  }));
  snap.dataHash = dataHashForSnapshots([snap]);
  return snap;
}

// Three identical 1 NEAR transfers to the same counterparty: the
// repeated_transfers flag fires, and that counterparty is labelled
// suspicious while the other outside counterparty stays unknown.
function flaggedSnapshot() {
  const snap = sampledSnapshot();
  snap.txs = [
    ...snap.txs,
    tx({ hash: 'C'.repeat(43) }),
    tx({ hash: 'D'.repeat(43) }),
  ];
  snap.dataHash = dataHashForSnapshots([snap]);
  return snap;
}

function checkByName(result, name) {
  const found = result.checks.find((c) => c.check === name);
  assert.ok(found, `expected a ${name} check`);
  return found;
}

// The verifier portal (public/verify.html) in a VM, same helper shape
// as test/verify-report.test.mjs: the page and tweetnacl share one
// realm, exactly as in the browser.
function loadPageVerify() {
  const html = readFileSync(new URL('../public/verify.html', import.meta.url), 'utf8');
  const match = html.match(/<script>([\s\S]*?)<\/script>/);
  assert.ok(match, 'verify.html must contain one inline <script> block');
  const sandbox = {
    window: {},
    crypto: globalThis.crypto,
    TextEncoder: globalThis.TextEncoder,
    TextDecoder: globalThis.TextDecoder,
    atob: globalThis.atob,
    btoa: globalThis.btoa,
    console,
  };
  vm.createContext(sandbox);
  sandbox.self = sandbox;
  vm.runInContext(readFileSync(new URL('../public/js/nacl.min.js', import.meta.url), 'utf8'), sandbox);
  vm.runInContext(match[1], sandbox);
  assert.ok(sandbox.window.VeilProofVerify, 'page script must expose window.VeilProofVerify');
  return sandbox.window.VeilProofVerify;
}

const FULL_ATTESTATION = {
  status: 'VERIFIED',
  method: 'near-ai-cloud-dcap',
  model: 'z-ai/glm-5.3-flash',
  nonceMatched: true,
  quoteVerified: true,
  signatureVerified: true,
  measurementsChecked: true,
  expiresAt: '2027-11-06T00:00:00.000Z',
  details: 'Quote, signature and measurements all checked against the reference values.',
};

test('model: sampled scored salted report verifies with five separate statuses', () => {
  const f = scoredSalted(sampledSnapshot());
  const result = verifyReport({
    report: f.report,
    onchainRecord: f.onchainRecord,
    disclosurePackage: f.disclosurePackage,
    policy: f.policy,
    nowNs: f.nowNs,
  });
  assert.equal(result.valid, true);
  assert.equal(result.checks.length, 10);
  assert.equal(result.checks.every((c) => c.passed), true);
  assert.equal(result.source_status.status, 'VERIFIED');
  assert.equal(result.computation_status.status, 'VERIFIED');
  assert.equal(result.report_integrity_status.status, 'VERIFIED');
  assert.equal(result.privacy_status.status, 'PRIVATE');
  // No AI summary is attached, so the attestation is honestly
  // UNVERIFIED, not verified: nothing was rechecked.
  assert.equal(result.attestation_status.status, 'UNVERIFIED');
  // The sampling record is describeSampling on the disclosure bundle.
  const expectedSampling = describeSampling({ wallets: [f.snapshot] });
  assert.deepEqual(result.sampling, expectedSampling);
  assert.equal(result.sampling.intervalBlocks, 900);
  assert.equal(result.sampling.sampleCount, 4);
  assert.equal(result.sampling.oldestBlock, 100);
  assert.equal(result.sampling.newestBlock, 2800);
  assert.equal(result.sampling.lowestObservedSampledBalance, '5000000000000000000000000');
  assert.equal(result.sampling.completeness, 'complete');
  assert.equal(result.sampling.wideIntervalWarning, null);
  // The score limits are the recomputed score's own flags and labels.
  const expectedScore = computeScore(
    f.snapshot,
    { txWindowDays: 30, volumeWindowDays: 30, noFailedWindowDays: 30 },
    NOW_NS,
  );
  assert.equal(result.score.band, expectedScore.band);
  assert.deepEqual(result.score.riskFlags, expectedScore.riskFlags);
  assert.deepEqual(result.score.counterpartyLabels, expectedScore.counterpartyLabels);
  assert.deepEqual(result.score.counterpartySummary, expectedScore.counterpartySummary);
  assert.equal(result.score.disclaimer, expectedScore.disclaimer);
  assert.equal(
    result.score.counterpartyLabels.find((l) => l.account === 'bob.veilproof.testnet').label,
    'unknown',
  );
  assert.equal(
    result.score.counterpartyLabels.find((l) => l.account === 'carol.veilproof.testnet').label,
    'unknown',
  );
  const summary = summariseVerification(result);
  assert.equal(summary.headline, 'Checks pass, AI attestation not verified.');
  assert.equal(summary.tone, 'warn');
});

test('model: attestation input VERIFIED only when every check was confirmed', () => {
  const f = scoredSalted(sampledSnapshot());
  const base = {
    report: f.report,
    onchainRecord: f.onchainRecord,
    disclosurePackage: f.disclosurePackage,
    policy: f.policy,
    nowNs: f.nowNs,
  };
  const verified = verifyReport({ ...base, attestation: FULL_ATTESTATION });
  assert.equal(verified.attestation_status.status, 'VERIFIED');
  assert.equal(summariseVerification(verified).headline, 'Verified: every check passed.');
  assert.equal(summariseVerification(verified).tone, 'ok');

  // One check merely unconfirmed: UNVERIFIED, never VERIFIED.
  const unconfirmed = verifyReport({
    ...base,
    attestation: { ...FULL_ATTESTATION, measurementsChecked: null },
  });
  assert.equal(unconfirmed.attestation_status.status, 'UNVERIFIED');

  // One check failed: FAILED.
  const failed = verifyReport({
    ...base,
    attestation: { ...FULL_ATTESTATION, quoteVerified: false },
  });
  assert.equal(failed.attestation_status.status, 'FAILED');
  assert.equal(summariseVerification(failed).headline, 'Checks pass, but the AI attestation failed.');

  // All checks confirmed but the evidence expired: EXPIRED.
  const expired = verifyReport({
    ...base,
    attestation: { ...FULL_ATTESTATION, expiresAt: '2026-01-01T00:00:00.000Z' },
  });
  assert.equal(expired.attestation_status.status, 'EXPIRED');
  assert.equal(summariseVerification(expired).headline, 'Checks pass, but the AI attestation expired.');

  // A FAILED or EXPIRED input passes through unchanged.
  assert.equal(
    verifyReport({ ...base, attestation: { ...FULL_ATTESTATION, status: 'FAILED', error: 'quote rejected' } })
      .attestation_status.status,
    'FAILED',
  );
  assert.equal(
    verifyReport({ ...base, attestation: { ...FULL_ATTESTATION, status: 'EXPIRED' } }).attestation_status.status,
    'EXPIRED',
  );
});

test('model: attestation derived from the AI summary can never reach VERIFIED', () => {
  const attestedSummary = {
    provider: 'near-ai',
    model: 'z-ai/glm-5.3-flash',
    attestation: { verifiable: true, nonceMatched: true, ref: 'e4f53f' },
  };
  const f = scoredSalted(sampledSnapshot(), { aiSummary: attestedSummary });
  const result = verifyReport({
    report: f.report,
    onchainRecord: f.onchainRecord,
    disclosurePackage: f.disclosurePackage,
    policy: f.policy,
    nowNs: f.nowNs,
  });
  // The nonce matched when the analysis ran, but this verifier did
  // not recheck the quote, signature or measurements.
  assert.equal(result.attestation_status.status, 'UNVERIFIED');
  assert.equal(result.attestation_status.nonceMatched, true);
  assert.equal(result.valid, true);

  const failedSummary = {
    provider: 'near-ai',
    model: 'z-ai/glm-5.3-flash',
    attestation: { verifiable: false, nonceMatched: false, ref: null },
  };
  const g = scoredSalted(sampledSnapshot(), { aiSummary: failedSummary });
  const failed = verifyReport({
    report: g.report,
    onchainRecord: g.onchainRecord,
    disclosurePackage: g.disclosurePackage,
    policy: g.policy,
    nowNs: g.nowNs,
  });
  assert.equal(failed.attestation_status.status, 'FAILED');
  assert.equal(failed.valid, true);
});

test('model: revoked report shows REVOKED and does not verify', () => {
  const f = scoredSalted(sampledSnapshot());
  const result = verifyReport({
    report: f.report,
    onchainRecord: onchainRecordFor(f.report, { valid: false }),
    disclosurePackage: f.disclosurePackage,
    policy: f.policy,
    nowNs: f.nowNs,
  });
  assert.equal(result.valid, false);
  assert.equal(result.report_integrity_status.status, 'REVOKED');
  const summary = summariseVerification(result);
  assert.equal(summary.headline, 'Revoked: this report was withdrawn from the registry.');
  assert.equal(summary.tone, 'bad');
  assert.ok(summary.failed.includes('report_integrity_status'));
});

test('model: expired report shows EXPIRED and does not verify', () => {
  const f = scoredSalted(sampledSnapshot(), { expiresAt: (NOW_NS - DAY_NS).toString() });
  const result = verifyReport({
    report: f.report,
    onchainRecord: f.onchainRecord,
    disclosurePackage: f.disclosurePackage,
    policy: f.policy,
    nowNs: f.nowNs,
  });
  assert.equal(result.valid, false);
  assert.equal(result.report_integrity_status.status, 'EXPIRED');
  const summary = summariseVerification(result);
  assert.equal(summary.headline, 'Expired: this report is past its expiry date.');
  assert.equal(summary.tone, 'bad');
});

test('model: legacy exact-values report is PARTIALLY_DISCLOSED, still verifies', () => {
  const snap = snapshot();
  const { claims } = evaluateClaims(snap, POLICY, NOW_NS);
  const report = buildReport({
    proverAddressHash: sha256Hex(ADDRESS),
    claims,
    policyVersion: POLICY_VERSION,
    aiSummary: null,
    evidenceRefs: { dataHash: snap.dataHash, attestationRef: null },
    expiresAt: EXPIRES_AT,
    includeExactValues: true,
  });
  const result = verifyReport({
    report,
    onchainRecord: onchainRecordFor(report),
    disclosurePackage: buildDisclosurePackage(report, ADDRESS, snap),
    policy: POLICY,
    nowNs: NOW_NS,
  });
  assert.equal(result.valid, true);
  assert.equal(result.privacy_status.status, 'PARTIALLY_DISCLOSED');
  assert.ok(summariseVerification(result).notes.some((n) => n.startsWith('Privacy:')));
});

test('model: no samples gives an empty sampling record, not a fabricated one', () => {
  const f = scoredSalted(snapshot());
  const result = verifyReport({
    report: f.report,
    onchainRecord: f.onchainRecord,
    disclosurePackage: f.disclosurePackage,
    policy: f.policy,
    nowNs: f.nowNs,
  });
  assert.equal(result.valid, true);
  assert.equal(result.sampling.sampleCount, 0);
  assert.equal(result.sampling.completeness, 'none');
  assert.equal(result.sampling.lowestObservedSampledBalance, null);
  assert.equal(result.sampling.intervalBlocks, null);
});

test('model: too few samples carries a wide interval warning object', () => {
  const f = scoredSalted(fewSampleSnapshot());
  const result = verifyReport({
    report: f.report,
    onchainRecord: f.onchainRecord,
    disclosurePackage: f.disclosurePackage,
    policy: f.policy,
    nowNs: f.nowNs,
  });
  assert.equal(result.valid, true);
  assert.equal(result.sampling.sampleCount, 2);
  assert.ok(result.sampling.wideIntervalWarning);
  assert.equal(result.sampling.wideIntervalWarning.reason, 'too_few_samples');
  assert.ok(summariseVerification(result).notes.some((n) => n.startsWith('Sampling:')));
});

test('model: flagged snapshot shows a real risk flag and a suspicious counterparty', () => {
  const f = scoredSalted(flaggedSnapshot());
  const result = verifyReport({
    report: f.report,
    onchainRecord: f.onchainRecord,
    disclosurePackage: f.disclosurePackage,
    policy: f.policy,
    nowNs: f.nowNs,
  });
  assert.equal(result.valid, true);
  assert.ok(result.score.riskFlags.some((flag) => flag.type === 'repeated_transfers'));
  assert.equal(
    result.score.counterpartyLabels.find((l) => l.account === 'bob.veilproof.testnet').label,
    'suspicious',
  );
  assert.equal(
    result.score.counterpartyLabels.find((l) => l.account === 'carol.veilproof.testnet').label,
    'unknown',
  );
  assert.ok(summariseVerification(result).notes.some((n) => n.startsWith('Credit score:')));
});

test('model: live demo claim b05bf4684960ee83 verifies end to end', () => {
  const report = JSON.parse(readFileSync(new URL('../public/demo-report.json', import.meta.url), 'utf8'));
  const disclosurePackage = JSON.parse(readFileSync(new URL('../public/demo-disclosure.json', import.meta.url), 'utf8'));
  const policy = JSON.parse(readFileSync(new URL('../public/demo-policy.json', import.meta.url), 'utf8'));
  const nowNs = BigInt(Date.parse(report.createdAt)) * 1000000n;
  const result = verifyReport({
    report,
    onchainRecord: {
      report_hash: reportHash(report),
      evidence_hash: evidenceHash(report.evidenceRefs),
      policy_hash: policyHash(report.policyVersion, policy),
      valid: true,
    },
    disclosurePackage,
    policy,
    nowNs,
  });
  assert.equal(result.valid, true);
  assert.equal(result.checks.length, 10);
  assert.equal(result.checks.every((c) => c.passed), true);
  assert.equal(result.source_status.status, 'VERIFIED');
  assert.equal(result.computation_status.status, 'VERIFIED');
  assert.equal(result.report_integrity_status.status, 'VERIFIED');
  assert.equal(result.privacy_status.status, 'PRIVATE');
  // The AI analysis ran with a matching nonce, but the quote,
  // signature and measurements were never rechecked from the report.
  assert.equal(result.attestation_status.status, 'UNVERIFIED');
  assert.equal(result.sampling.sampleCount, 4);
  assert.equal(result.sampling.intervalBlocks, 900);
  assert.equal(result.sampling.oldestBlock, 276512600);
  assert.equal(result.sampling.newestBlock, 276515300);
  assert.equal(result.sampling.lowestObservedSampledBalance, '12647996057936901200000000');
  assert.equal(result.sampling.completeness, 'complete');
  assert.equal(result.sampling.wideIntervalWarning, null);
  assert.equal(result.score.band, 'solid');
  assert.equal(result.score.version, 'score-v2');
  // The demo's outside activity is funnelled through one counterparty,
  // so the detector flags concentration and labels it suspicious.
  assert.ok(result.score.riskFlags.some((flag) => flag.type === 'concentrated_counterparty'));
  assert.ok(result.score.riskFlags.some((flag) => flag.type === 'internal_transfers'));
  assert.equal(
    result.score.counterpartyLabels.find((l) => l.account === 'veilproof.testnet').label,
    'suspicious',
  );
  assert.deepEqual(result.score.counterpartySummary, { own: 2, unknown: 0, suspicious: 1 });
  assert.equal(summariseVerification(result).headline, 'Checks pass, AI attestation not verified.');
});

test('parity: browser module and page agree with Node on the sampled fixture', async () => {
  const f = scoredSalted(sampledSnapshot());
  const args = {
    report: f.report,
    onchainRecord: f.onchainRecord,
    disclosurePackage: f.disclosurePackage,
    policy: f.policy,
    nowNs: f.nowNs,
  };
  const nodeResult = verifyReport(args);
  const browserResult = await verifyReportBrowser(args);
  assert.deepEqual(browserResult, nodeResult);
  const page = loadPageVerify();
  const pageResult = await page.verifyReport(args);
  // The page result is built inside the vm realm, so its objects
  // carry a different prototype and deepStrictEqual would fail on
  // that alone. Compare the serialised form: content is what matters.
  assert.equal(JSON.stringify(pageResult), JSON.stringify(nodeResult));
  // The demo claim agrees across all three copies too.
  const report = JSON.parse(readFileSync(new URL('../public/demo-report.json', import.meta.url), 'utf8'));
  const disclosurePackage = JSON.parse(readFileSync(new URL('../public/demo-disclosure.json', import.meta.url), 'utf8'));
  const policy = JSON.parse(readFileSync(new URL('../public/demo-policy.json', import.meta.url), 'utf8'));
  const demoArgs = {
    report,
    onchainRecord: {
      report_hash: reportHash(report),
      evidence_hash: evidenceHash(report.evidenceRefs),
      policy_hash: policyHash(report.policyVersion, policy),
      valid: true,
    },
    disclosurePackage,
    policy,
    nowNs: BigInt(Date.parse(report.createdAt)) * 1000000n,
  };
  const demoNode = verifyReport(demoArgs);
  assert.deepEqual(await verifyReportBrowser(demoArgs), demoNode);
  assert.equal(JSON.stringify(await page.verifyReport(demoArgs)), JSON.stringify(demoNode));
});

test('panels: page builder renders the five statuses, the checks and the panels', async () => {
  const f = scoredSalted(flaggedSnapshot());
  const result = verifyReport({
    report: f.report,
    onchainRecord: f.onchainRecord,
    disclosurePackage: f.disclosurePackage,
    policy: f.policy,
    nowNs: f.nowNs,
  });
  const page = loadPageVerify();
  const panels = page.buildStatusPanelsHtml(result, f.report);
  const all = Object.values(panels).join('\n');
  // No single VALID/INVALID headline anywhere.
  assert.equal(all.includes('VALID, this report verifies.'), false);
  assert.equal(all.includes('INVALID, this report does not verify.'), false);
  // The summary fragment carries the five status rows and the notes
  // (the headline itself is rendered in the banner by
  // summariseVerification, covered in the model tests above).
  assert.ok(panels.summary.includes('Attestation: not verified, see the attestation panel for what was and was not checked.'));
  for (const status of ['VERIFIED', 'UNVERIFIED', 'PRIVATE']) {
    assert.ok(panels.summary.includes(status), `summary must show ${status}`);
  }
  // Privacy panel: private, and the registry-owner hard limit.
  assert.ok(panels.privacy.includes('PRIVATE'));
  assert.ok(panels.privacy.includes('registry'));
  // Attestation panel: UNVERIFIED, with what was not rechecked.
  assert.ok(panels.attestation.includes('UNVERIFIED'));
  assert.ok(panels.attestation.includes('quote'));
  // Sampling panel: interval, count, lowest balance, completeness.
  assert.ok(panels.sampling.includes('900'));
  assert.ok(panels.sampling.includes('5 NEAR'));
  assert.ok(panels.sampling.includes('complete: every requested reading is present'));
  // Score panel: band, risk flag, counterparty labels, disclaimer.
  assert.ok(panels.score.includes('solid'));
  assert.ok(panels.score.includes('repeated_transfers'));
  assert.ok(panels.score.includes('suspicious'));
  assert.ok(panels.score.includes('unknown'));
  assert.ok(panels.score.includes('not a guarantee of repayment'));
  // The page builder and the browser module builder produce identical HTML.
  // (Compare serialised: the page panels object is built in the vm realm.)
  assert.equal(JSON.stringify(panels), JSON.stringify(buildPanelsBrowser(result, f.report)));
});

test('panels: revoked and expired reports render the red state in the panels', () => {
  const page = loadPageVerify();
  const revokedFixture = scoredSalted(sampledSnapshot());
  const revoked = verifyReport({
    report: revokedFixture.report,
    onchainRecord: onchainRecordFor(revokedFixture.report, { valid: false }),
    disclosurePackage: revokedFixture.disclosurePackage,
    policy: revokedFixture.policy,
    nowNs: revokedFixture.nowNs,
  });
  const revokedPanels = page.buildStatusPanelsHtml(revoked, revokedFixture.report);
  assert.ok(revokedPanels.summary.includes('REVOKED'));
  assert.ok(revokedPanels.integrity.includes('REVOKED'));

  const expiredFixture = scoredSalted(sampledSnapshot(), { expiresAt: (NOW_NS - DAY_NS).toString() });
  const expired = verifyReport({
    report: expiredFixture.report,
    onchainRecord: expiredFixture.onchainRecord,
    disclosurePackage: expiredFixture.disclosurePackage,
    policy: expiredFixture.policy,
    nowNs: expiredFixture.nowNs,
  });
  const expiredPanels = page.buildStatusPanelsHtml(expired, expiredFixture.report);
  assert.ok(expiredPanels.summary.includes('EXPIRED'));
  assert.ok(expiredPanels.integrity.includes('EXPIRED'));

  const noSampleFixture = scoredSalted(snapshot());
  const noSample = verifyReport({
    report: noSampleFixture.report,
    onchainRecord: noSampleFixture.onchainRecord,
    disclosurePackage: noSampleFixture.disclosurePackage,
    policy: noSampleFixture.policy,
    nowNs: noSampleFixture.nowNs,
  });
  const noSamplePanels = page.buildStatusPanelsHtml(noSample, noSampleFixture.report);
  assert.ok(noSamplePanels.sampling.includes('No balance samples were disclosed'));
});

test('summary: the three copies agree on headline, tone, notes and failed fields', () => {
  const page = loadPageVerify();
  const fixtures = [
    scoredSalted(sampledSnapshot()),
    scoredSalted(sampledSnapshot(), { expiresAt: (NOW_NS - DAY_NS).toString() }),
  ];
  for (const f of fixtures) {
    const result = verifyReport({
      report: f.report,
      onchainRecord: f.onchainRecord,
      disclosurePackage: f.disclosurePackage,
      policy: f.policy,
      nowNs: f.nowNs,
    });
    assert.deepEqual(summariseBrowser(result), summariseVerification(result));
    assert.equal(JSON.stringify(page.summariseVerification(result)), JSON.stringify(summariseVerification(result)));
  }
  // A revoked result agrees too.
  const f = scoredSalted(sampledSnapshot());
  const revoked = verifyReport({
    report: f.report,
    onchainRecord: onchainRecordFor(f.report, { valid: false }),
    disclosurePackage: f.disclosurePackage,
    policy: f.policy,
    nowNs: f.nowNs,
  });
  assert.deepEqual(summariseBrowser(revoked), summariseVerification(revoked));
  assert.equal(JSON.stringify(page.summariseVerification(revoked)), JSON.stringify(summariseVerification(revoked)));
});

test('static: overstated attestation strings are gone and the new panels exist', () => {
  const demoJs = readFileSync(new URL('../public/demo.js', import.meta.url), 'utf8');
  const appJs = readFileSync(new URL('../public/app.js', import.meta.url), 'utf8');
  const indexHtml = readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
  const verifyHtml = readFileSync(new URL('../public/verify.html', import.meta.url), 'utf8');
  const css = readFileSync(new URL('../public/style.css', import.meta.url), 'utf8');
  for (const [name, text] of [
    ['demo.js', demoJs],
    ['app.js', appJs],
    ['index.html', indexHtml],
    ['verify.html', verifyHtml],
  ]) {
    assert.equal(text.includes('verified (nonce matched)'), false, `${name} must not claim attestation verified`);
    assert.equal(text.includes('attested (nonce matched)'), false, `${name} must not claim attestation attested`);
    assert.equal(text.includes('NEAR AI Cloud, attested'), false, `${name} must not claim NEAR AI attestation`);
    assert.equal(text.includes('VALID, this report verifies.'), false, `${name} must not carry the old VALID headline`);
  }
  assert.ok(indexHtml.includes('id="demoPanels"'), 'landing page must carry the demo panels container');
  assert.ok(indexHtml.includes('How verification works'), 'landing page must explain how verification works');
  assert.ok(indexHtml.includes('What the verifier can and cannot learn'), 'landing page must state what the verifier can and cannot learn');
  for (const id of ['statuses', 'privacyPanel', 'attestationPanel', 'integrityPanel', 'samplingPanel', 'scorePanel']) {
    assert.ok(verifyHtml.includes(`id="${id}"`), `verify.html must carry the ${id} panel`);
  }
  assert.ok(verifyHtml.includes('How verification works'), 'verify.html must explain how verification works');
  assert.ok(verifyHtml.includes('What the verifier can and cannot learn'), 'verify.html must state what the verifier can and cannot learn');
  assert.ok(css.includes('.banner.warn'), 'style.css must carry the amber banner state');
  assert.ok(css.includes('.pill'), 'style.css must carry the status pill');
});
