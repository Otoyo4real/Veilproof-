// VeilProof report + disclosure tests — pure, no network.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { evaluateClaims } from '../src/claims-engine.js';
import { computeDataHash } from '../src/onchain.js';
import {
  canonicalJson,
  buildReport,
  reportHash,
  evidenceHash,
  policyHash,
} from '../src/report.js';
import { buildDisclosurePackage, assertPublicReportClean } from '../src/disclosure.js';

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
  snap.dataHash = computeDataHash(snap.account.accountId, snap.account.amount, snap.account.locked, snap.txs);
  return snap;
}

// A genuine report: all five claims pass (balance 5 NEAR, staked 2
// NEAR, 2 txs in 30 days, 1.5 NEAR volume, no failures in window).
function genuineReport() {
  const snap = snapshot();
  const { claims } = evaluateClaims(snap, POLICY, NOW_NS);
  const report = buildReport({
    proverAddressHash: sha256Hex(ADDRESS),
    claims,
    policyVersion: POLICY_VERSION,
    aiSummary: null,
    evidenceRefs: { dataHash: snap.dataHash, attestationRef: null },
    expiresAt: EXPIRES_AT,
  });
  return { snapshot: snap, claims, report };
}

test('canonicalJson: keys sorted recursively, arrays keep order', () => {
  assert.equal(canonicalJson({ b: 1, a: 2 }), '{"a":2,"b":1}');
  assert.equal(
    canonicalJson({ z: { b: 1, a: { d: 4, c: 3 } }, a: [{ b: 1, a: 2 }] }),
    '{"a":[{"a":2,"b":1}],"z":{"a":{"c":3,"d":4},"b":1}}',
  );
  const one = canonicalJson({ x: { b: 1, a: 2 }, y: [3, { d: 4, c: 5 }] });
  const two = canonicalJson({ y: [3, { c: 5, d: 4 }], x: { a: 2, b: 1 } });
  assert.equal(one, two);
  assert.equal(canonicalJson(null), 'null');
  assert.equal(canonicalJson('a"b'), '"a\\"b"');
  assert.throws(() => canonicalJson(10n), /cannot serialise bigint/);
});

test('buildReport: shape, ids, and defaults', () => {
  const { report } = genuineReport();
  assert.match(report.reportId, /^[0-9a-f]{16}$/);
  assert.equal(report.prover, sha256Hex(ADDRESS));
  assert.ok(!Number.isNaN(Date.parse(report.createdAt)));
  assert.equal(report.claims.length, 5);
  assert.equal(report.policyVersion, POLICY_VERSION);
  assert.equal(report.aiSummary, null);
  assert.equal(report.evidenceRefs.attestationRef, null);
  assert.equal(report.expiresAt, EXPIRES_AT);
  assert.deepEqual(report.disclosed, [
    'balance_at_least',
    'staked_at_least',
    'tx_count_in_window',
    'volume_in_window',
    'no_failed_txs_in_window',
  ]);
  assert.deepEqual(Object.keys(report).sort(), [
    'aiSummary',
    'claims',
    'createdAt',
    'disclosed',
    'evidenceRefs',
    'expiresAt',
    'policyVersion',
    'prover',
    'reportId',
  ]);
  // Two reports are never the same id.
  const { report: second } = genuineReport();
  assert.notEqual(report.reportId, second.reportId);
});

test('buildReport: disclosedFields filters the report claims', () => {
  const { snapshot: snap, claims } = genuineReport();
  const report = buildReport({
    proverAddressHash: sha256Hex(ADDRESS),
    claims,
    policyVersion: POLICY_VERSION,
    aiSummary: null,
    evidenceRefs: { dataHash: snap.dataHash, attestationRef: null },
    expiresAt: EXPIRES_AT,
    disclosedFields: ['volume_in_window', 'balance_at_least'],
  });
  assert.deepEqual(report.disclosed, ['balance_at_least', 'volume_in_window']);
  assert.deepEqual(
    report.claims.map((c) => c.id),
    ['balance_at_least', 'volume_in_window'],
  );
  // Disclosing nothing is allowed: an empty report is still a report.
  const empty = buildReport({
    proverAddressHash: sha256Hex(ADDRESS),
    claims,
    policyVersion: POLICY_VERSION,
    aiSummary: null,
    evidenceRefs: { dataHash: snap.dataHash, attestationRef: null },
    expiresAt: EXPIRES_AT,
    disclosedFields: [],
  });
  assert.deepEqual(empty.claims, []);
  assert.deepEqual(empty.disclosed, []);
});

test('buildReport: rejects bad inputs', () => {
  const { snapshot: snap, claims } = genuineReport();
  const base = {
    proverAddressHash: sha256Hex(ADDRESS),
    claims,
    policyVersion: POLICY_VERSION,
    aiSummary: null,
    evidenceRefs: { dataHash: snap.dataHash, attestationRef: null },
    expiresAt: EXPIRES_AT,
  };
  assert.throws(() => buildReport({ ...base, disclosedFields: ['no_such_claim'] }), /unknown claim id/);
  assert.throws(() => buildReport({ ...base, proverAddressHash: 'xyz' }), /64-char lowercase hex/);
  assert.throws(() => buildReport({ ...base, proverAddressHash: sha256Hex(ADDRESS).toUpperCase() }), /64-char lowercase hex/);
  // A free-form string summary is a fake summary. Null or structured only.
  assert.throws(() => buildReport({ ...base, aiSummary: 'looks good' }), /null or a structured object/);
  assert.throws(() => buildReport({ ...base, expiresAt: 'tomorrow' }), /nanosecond epoch/);
  assert.throws(() => buildReport({ ...base, expiresAt: 1794566400000000000 }), /nanosecond epoch/);
  assert.throws(() => buildReport({ ...base, evidenceRefs: { dataHash: 'abc', attestationRef: null } }), /64-char lowercase hex/);
  assert.throws(() => buildReport({ ...base, claims: 'not-an-array' }), /claims must be an array/);
  // A structured summary object is accepted (for when the AI lands).
  const withSummary = buildReport({ ...base, aiSummary: { model: 'x', text: 'cash flow is positive' } });
  assert.equal(withSummary.aiSummary.text, 'cash flow is positive');
});

test('reportHash: deterministic, tamper-sensitive, strips hash fields', () => {
  const { report } = genuineReport();
  const h1 = reportHash(report);
  assert.match(h1, /^[0-9a-f]{64}$/);
  assert.equal(reportHash(report), h1);
  const tampered = JSON.parse(JSON.stringify(report));
  tampered.claims[0].value = '1';
  assert.notEqual(reportHash(tampered), h1);
  // An annotated copy (hash fields present) hashes the same: the
  // payload is the report minus the hash fields.
  const annotated = { ...report, reportHash: 'a'.repeat(64), evidenceHash: 'b'.repeat(64), policyHash: 'c'.repeat(64) };
  assert.equal(reportHash(annotated), h1);
});

test('evidenceHash and policyHash: deterministic and sensitive', () => {
  const { snapshot: snap } = genuineReport();
  const bundle = { dataHash: snap.dataHash, attestationRef: null };
  assert.equal(evidenceHash(bundle), evidenceHash({ dataHash: snap.dataHash, attestationRef: null }));
  assert.notEqual(evidenceHash(bundle), evidenceHash({ dataHash: snap.dataHash, attestationRef: 'att-1' }));
  assert.throws(() => evidenceHash({ dataHash: snap.dataHash, attestationRef: 5 }), /null or a string/);
  assert.equal(policyHash(POLICY_VERSION, POLICY), policyHash(POLICY_VERSION, POLICY));
  assert.notEqual(policyHash(POLICY_VERSION, POLICY), policyHash(POLICY_VERSION, { ...POLICY, minTxCount: 2 }));
  assert.notEqual(policyHash(POLICY_VERSION, POLICY), policyHash('other-version', POLICY));
});

test('buildDisclosurePackage: private package, deep copy, wrong address refused', () => {
  const { snapshot: snap, report } = genuineReport();
  const pkg = buildDisclosurePackage(report, ADDRESS, snap);
  assert.equal(pkg.reportId, report.reportId);
  assert.equal(pkg.address, ADDRESS);
  assert.equal(pkg.dataHash, snap.dataHash);
  assert.deepEqual(pkg.snapshot, snap);
  // Mutating the package must not mutate the caller's snapshot.
  pkg.snapshot.account.amount = '0';
  assert.equal(snap.account.amount, '5000000000000000000000000');
  assert.throws(
    () => buildDisclosurePackage(report, 'mallory.veilproof.testnet', snap),
    /does not hash to report\.prover/,
  );
  assert.throws(() => buildDisclosurePackage(report, ADDRESS, { account: {}, txs: [] }), /dataHash/);
});

test('assertPublicReportClean: clean passes, leaks throw', () => {
  const { snapshot: snap, report } = genuineReport();
  const txHashes = snap.txs.map((t) => t.hash);
  assert.equal(assertPublicReportClean(report, ADDRESS, txHashes), true);
  // Address smuggled into a field.
  const withAddress = { ...report, aiSummary: { note: `for ${ADDRESS}` } };
  assert.throws(() => assertPublicReportClean(withAddress, ADDRESS, txHashes), /leaks the prover address/);
  // A tx hash smuggled into a claim threshold.
  const withTx = JSON.parse(JSON.stringify(report));
  withTx.claims[0].threshold = txHashes[0];
  assert.throws(() => assertPublicReportClean(withTx, ADDRESS, txHashes), /leaks transaction hash/);
  // The prover commitment itself is supposed to be there: not a leak.
  assert.equal(assertPublicReportClean(report, ADDRESS, []), true);
});

test('null AI summary is allowed and never auto-filled', () => {
  const { snapshot: snap, claims } = genuineReport();
  const omitted = buildReport({
    proverAddressHash: sha256Hex(ADDRESS),
    claims,
    policyVersion: POLICY_VERSION,
    evidenceRefs: { dataHash: snap.dataHash, attestationRef: null },
    expiresAt: EXPIRES_AT,
  });
  assert.equal(omitted.aiSummary, null);
  // The report carries no analysis text anywhere.
  assert.equal(JSON.stringify(omitted).includes('analys'), false);
});
