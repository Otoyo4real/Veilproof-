// VeilProof frontend parity — public/js/* vs src/*.
//
// The browser cannot import ../src/ (Vercel serves only public/), so
// the prover page carries browser copies under public/js/:
// - canonical.js, claims-engine.js: verbatim copies (byte-identical).
// - report.js, disclosure.js, onchain.js: mirrors — same shapes and
//   validation, but Web Crypto (async) instead of node:crypto, so the
//   hashing functions are async here.
// - crypto.js: the browser's hash primitive (no Node counterpart).
// - demo-history.json: a copy of demo/history.json for the demo loader.
//
// This file asserts the two paths agree on identical fixtures, so a
// report built in the browser hashes exactly like one built in Node
// (and verifies exactly like one checked by src/verify-report.js).

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

// Node path.
import { canonicalJson as nodeCanonical } from '../src/canonical.js';
import * as nodeEngine from '../src/claims-engine.js';
import * as nodeReport from '../src/report.js';
import * as nodeDisclosure from '../src/disclosure.js';
import * as nodeOnchain from '../src/onchain.js';
import * as nodeScore from '../src/score.js';

// Browser path.
import { canonicalJson as browserCanonical } from '../public/js/canonical.js';
import * as browserEngine from '../public/js/claims-engine.js';
import * as browserReport from '../public/js/report.js';
import * as browserDisclosure from '../public/js/disclosure.js';
import * as browserOnchain from '../public/js/onchain.js';
import * as browserScore from '../public/js/score.js';
import { sha256Hex as browserSha256Hex, randomHex } from '../public/js/crypto.js';

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
const NOW_NS = '1793958600000000000';

const TXS = [
  {
    hash: 'B'.repeat(43),
    senderId: 'alice.testnet',
    receiverId: 'bob.testnet',
    amountYocto: '1500000000000000000000000',
    status: 'Success',
    blockHeight: 99,
    blockTimestampNs: '1793958583519543793',
  },
  {
    hash: 'A'.repeat(43),
    senderId: 'carol.testnet',
    receiverId: 'alice.testnet',
    amountYocto: '500000000000000000000000',
    status: 'Success',
    blockHeight: 98,
    blockTimestampNs: '1793958500000000000',
  },
];

const SNAPSHOT = {
  account: {
    accountId: 'alice.testnet',
    amount: '5000000000000000000000000',
    locked: '2000000000000000000000000',
    storage_usage: 1000,
    blockHeight: 100,
  },
  txs: TXS,
  blockHeight: 100,
  dataHash: nodeOnchain.computeDataHash('alice.testnet', '5000000000000000000000000', '2000000000000000000000000', TXS),
};

test('verbatim copies are byte-identical to src', () => {
  for (const name of ['canonical.js', 'claims-engine.js']) {
    const fromSrc = readFileSync(new URL(`../src/${name}`, import.meta.url), 'utf8');
    const fromPublic = readFileSync(new URL(`../public/js/${name}`, import.meta.url), 'utf8');
    assert.equal(fromPublic, fromSrc, `public/js/${name} drifted from src/${name} — copy it again`);
  }
  const historySrc = readFileSync(new URL('../demo/history.json', import.meta.url), 'utf8');
  const historyPublic = readFileSync(new URL('../public/demo-history.json', import.meta.url), 'utf8');
  assert.equal(historyPublic, historySrc, 'public/demo-history.json drifted from demo/history.json');
});

test('canonicalJson parity on nested fixtures', () => {
  const fixture = {
    z: [3, 1, { b: undefined, a: 'x' }],
    a: { nested: { y: 2, x: [true, null, 's'] } },
    m: undefined,
    n: 0,
  };
  assert.equal(browserCanonical(fixture), nodeCanonical(fixture));
  assert.throws(() => browserCanonical(10n), /cannot serialise/);
  assert.throws(() => nodeCanonical(10n), /cannot serialise/);
});

test('claims engine parity: evaluateClaims and each claim fn', () => {
  assert.deepEqual(
    browserEngine.evaluateClaims(SNAPSHOT, POLICY, NOW_NS),
    nodeEngine.evaluateClaims(SNAPSHOT, POLICY, NOW_NS),
  );
  assert.deepEqual(
    browserEngine.balanceAtLeast(SNAPSHOT, POLICY.balanceAtLeastYocto),
    nodeEngine.balanceAtLeast(SNAPSHOT, POLICY.balanceAtLeastYocto),
  );
  assert.deepEqual(
    browserEngine.stakedAtLeast(SNAPSHOT, POLICY.stakedAtLeastYocto),
    nodeEngine.stakedAtLeast(SNAPSHOT, POLICY.stakedAtLeastYocto),
  );
  assert.deepEqual(
    browserEngine.txCountInWindow(SNAPSHOT, 30, NOW_NS),
    nodeEngine.txCountInWindow(SNAPSHOT, 30, NOW_NS),
  );
  assert.deepEqual(
    browserEngine.volumeInWindow(SNAPSHOT, 30, NOW_NS),
    nodeEngine.volumeInWindow(SNAPSHOT, 30, NOW_NS),
  );
  assert.deepEqual(
    browserEngine.noFailedTxsInWindow(SNAPSHOT, 30, NOW_NS),
    nodeEngine.noFailedTxsInWindow(SNAPSHOT, 30, NOW_NS),
  );
  assert.throws(
    () => browserEngine.evaluateClaims(SNAPSHOT, { minTxCount: 1 }, NOW_NS),
    /requires policy.txWindowDays/,
  );
});

test('computeDataHash parity (browser async vs Node sync)', async () => {
  const browserHash = await browserOnchain.computeDataHash(
    'alice.testnet',
    SNAPSHOT.account.amount,
    SNAPSHOT.account.locked,
    TXS,
  );
  assert.equal(browserHash, SNAPSHOT.dataHash);
  assert.equal(
    browserHash,
    nodeOnchain.computeDataHash('alice.testnet', SNAPSHOT.account.amount, SNAPSHOT.account.locked, TXS),
  );
  // Tx order must not matter on either path.
  assert.equal(
    await browserOnchain.computeDataHash('alice.testnet', SNAPSHOT.account.amount, SNAPSHOT.account.locked, [...TXS].reverse()),
    browserHash,
  );
});

test('report build + hashes parity', async () => {
  const prover = await browserSha256Hex('alice.testnet');
  const claims = nodeEngine.evaluateClaims(SNAPSHOT, POLICY, NOW_NS).claims;
  const args = {
    proverAddressHash: prover,
    claims,
    policyVersion: POLICY_VERSION,
    aiSummary: null,
    evidenceRefs: { dataHash: SNAPSHOT.dataHash, attestationRef: null },
    expiresAt: '1825497600000000000',
    disclosedFields: ['balance_at_least', 'volume_in_window'],
  };
  const nodeBuilt = nodeReport.buildReport(args);
  const browserBuilt = browserReport.buildReport(args);
  // reportId is random and createdAt is time-based on both paths; fix
  // them to compare everything else.
  nodeBuilt.reportId = 'fixed-report-id';
  browserBuilt.reportId = 'fixed-report-id';
  nodeBuilt.createdAt = '2026-11-06T00:00:00.000Z';
  browserBuilt.createdAt = '2026-11-06T00:00:00.000Z';
  assert.deepEqual(browserBuilt, nodeBuilt);

  assert.equal(await browserReport.reportHash(browserBuilt), nodeReport.reportHash(nodeBuilt));
  assert.equal(
    await browserReport.evidenceHash(browserBuilt.evidenceRefs),
    nodeReport.evidenceHash(nodeBuilt.evidenceRefs),
  );
  assert.equal(
    await browserReport.policyHash(POLICY_VERSION, POLICY),
    nodeReport.policyHash(POLICY_VERSION, POLICY),
  );
  assert.match(randomHex(8), /^[0-9a-f]{16}$/);
  assert.throws(() => browserReport.buildReport({ ...args, aiSummary: 'a string' }), /never a string/);
});

test('disclosure parity: package, clean check, leak tripwire', async () => {
  const prover = await browserSha256Hex('alice.testnet');
  const claims = nodeEngine.evaluateClaims(SNAPSHOT, POLICY, NOW_NS).claims;
  const report = nodeReport.buildReport({
    proverAddressHash: prover,
    claims,
    policyVersion: POLICY_VERSION,
    aiSummary: null,
    evidenceRefs: { dataHash: SNAPSHOT.dataHash, attestationRef: null },
    expiresAt: '1825497600000000000',
  });
  const nodePkg = nodeDisclosure.buildDisclosurePackage(report, 'alice.testnet', SNAPSHOT);
  const browserPkg = await browserDisclosure.buildDisclosurePackage(report, 'alice.testnet', SNAPSHOT);
  assert.deepEqual(browserPkg, nodePkg);
  assert.equal(browserDisclosure.assertPublicReportClean(report, 'alice.testnet', TXS.map((t) => t.hash)), true);
  assert.equal(nodeDisclosure.assertPublicReportClean(report, 'alice.testnet', TXS.map((t) => t.hash)), true);
  await assert.rejects(
    () => browserDisclosure.buildDisclosurePackage(report, 'mallory.testnet', SNAPSHOT),
    /does not hash to report.prover/,
  );
  // A report carrying the raw address trips the wire on both paths.
  const leaked = { ...report, note: 'alice.testnet' };
  assert.throws(() => browserDisclosure.assertPublicReportClean(leaked, 'alice.testnet', []), /leaks the prover address/);
  assert.throws(() => nodeDisclosure.assertPublicReportClean(leaked, 'alice.testnet', []), /leaks the prover address/);
  const leakedTx = { ...report, note: TXS[0].hash };
  assert.throws(
    () => browserDisclosure.assertPublicReportClean(leakedTx, 'alice.testnet', TXS.map((t) => t.hash)),
    /leaks transaction hash/,
  );
});

// Live smoke checks for the browser RPC path (one cheap call each).
// The balance is only asserted as a sanity band: the demo wallet was
// funded with 10 NEAR and the recorded demo transfers moved a net
// +1.15 NEAR in (see demo/history.json — the 0.5 NEAR link transfer
// from the linked wallet is the fifth entry), so it sits between 11
// and 12 NEAR. This is not a balance test — onchain.test.mjs owns that.
test('browser onchain live: getAccount returns the demo wallet', async () => {
  const account = await browserOnchain.getAccount('veilproof-demo.testnet');
  assert.equal(account.accountId, 'veilproof-demo.testnet');
  const amount = BigInt(account.amount);
  assert.ok(amount > 11n * 10n ** 24n && amount < 12n * 10n ** 24n, `unexpected demo balance ${account.amount}`);
  assert.ok(account.blockHeight > 0);
});

test('browser onchain live: fetchAccountSnapshot with no txs', async () => {
  const snap = await browserOnchain.fetchAccountSnapshot('veilproof-demo.testnet', []);
  assert.deepEqual(snap.txs, []);
  assert.equal(
    snap.dataHash,
    await browserOnchain.computeDataHash('veilproof-demo.testnet', snap.account.amount, snap.account.locked, []),
  );
});

test('score parity: browser and Node compute the same score', () => {
  const withSamples = {
    ...SNAPSHOT,
    balanceSamples: [
      { blockHeight: 90, amount: '5000000000000000000000000' },
      { blockHeight: 95, amount: '5000000000000000000000000' },
    ],
  };
  const windows = { txWindowDays: 30, volumeWindowDays: 30, noFailedWindowDays: 30 };
  assert.deepEqual(browserScore.computeScore(withSamples, windows, NOW_NS), nodeScore.computeScore(withSamples, windows, NOW_NS));
  assert.deepEqual(browserScore.computeScore({ wallets: [withSamples, SNAPSHOT] }, windows, NOW_NS), nodeScore.computeScore({ wallets: [withSamples, SNAPSHOT] }, windows, NOW_NS));
});

test('multi data hash parity: browser and Node agree on multi-wallet bundles', async () => {
  const second = {
    account: { accountId: 'bob.testnet', amount: '1000000000000000000000000', locked: '0', storage_usage: 1000, blockHeight: 100 },
    txs: [],
    blockHeight: 100,
  };
  assert.equal(await browserOnchain.dataHashForSnapshots([SNAPSHOT]), nodeOnchain.dataHashForSnapshots([SNAPSHOT]));
  assert.equal(await browserOnchain.dataHashForSnapshots([SNAPSHOT, second]), nodeOnchain.dataHashForSnapshots([SNAPSHOT, second]));
  assert.equal(
    await browserOnchain.computeMultiDataHash([SNAPSHOT, second]),
    nodeOnchain.computeMultiDataHash([SNAPSHOT, second]),
  );
});

test('report + disclosure parity with score and linked wallets', async () => {
  const prover = await browserSha256Hex('alice.testnet');
  const linked = await browserSha256Hex('bob.testnet');
  const claims = nodeEngine.evaluateClaims(SNAPSHOT, POLICY, NOW_NS).claims;
  const score = nodeScore.computeScore(SNAPSHOT, { txWindowDays: 30, volumeWindowDays: 30, noFailedWindowDays: 30 }, NOW_NS);
  const args = {
    proverAddressHash: prover,
    claims,
    policyVersion: POLICY_VERSION,
    aiSummary: null,
    evidenceRefs: { dataHash: SNAPSHOT.dataHash, attestationRef: null },
    expiresAt: '1825497600000000000',
    linkedProverHashes: [linked],
    score,
  };
  const nodeBuilt = nodeReport.buildReport(args);
  const browserBuilt = browserReport.buildReport(args);
  nodeBuilt.reportId = 'fixed-report-id';
  browserBuilt.reportId = 'fixed-report-id';
  nodeBuilt.createdAt = '2026-11-06T00:00:00.000Z';
  browserBuilt.createdAt = '2026-11-06T00:00:00.000Z';
  assert.deepEqual(browserBuilt, nodeBuilt);
  assert.equal(browserBuilt.score.value, score.value);
  assert.deepEqual(browserBuilt.linkedProvers, [linked]);
});
