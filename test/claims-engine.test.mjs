// VeilProof claims engine tests — pure, no network.
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  balanceAtLeast,
  stakedAtLeast,
  txCountInWindow,
  volumeInWindow,
  noFailedTxsInWindow,
  evaluateClaims,
} from '../src/claims-engine.js';

const DAY_NS = 86400n * 1_000_000_000n;
// Fixed "now" (ns) so every window test is deterministic.
const NOW = 1793958583519543793n;

function tx(overrides = {}) {
  return {
    hash: 'A'.repeat(43),
    senderId: 'alice.testnet',
    receiverId: 'bob.testnet',
    amountYocto: '0',
    status: 'Success',
    blockHeight: 100,
    blockTimestampNs: NOW.toString(),
    ...overrides,
  };
}

function snapshot(overrides = {}) {
  return {
    account: { accountId: 'alice.testnet', amount: '10000000000000000000000000', locked: '0', storage_usage: 182, blockHeight: 100 },
    txs: [],
    blockHeight: 100,
    dataHash: '0'.repeat(64),
    ...overrides,
  };
}

test('balanceAtLeast: exact threshold passes, 1 yocto below fails', () => {
  const s = snapshot();
  assert.equal(balanceAtLeast(s, '10000000000000000000000000').passed, true);
  assert.equal(balanceAtLeast(s, '10000000000000000000000001').passed, false);
  assert.equal(balanceAtLeast(s, '0').passed, true);
  const r = balanceAtLeast(s, '10000000000000000000000000');
  assert.equal(r.id, 'balance_at_least');
  assert.equal(r.value, '10000000000000000000000000');
  assert.equal(r.threshold, '10000000000000000000000000');
});

test('balanceAtLeast: BigInt amounts beyond Number.MAX_SAFE_INTEGER', () => {
  // 10^30 yocto — far beyond 2^53, must not lose precision.
  const huge = '1000000000000000000000000000000';
  const s = snapshot({ account: { accountId: 'alice.testnet', amount: huge, locked: '0', storage_usage: 182, blockHeight: 100 } });
  assert.equal(balanceAtLeast(s, huge).passed, true);
  assert.equal(balanceAtLeast(s, '1000000000000000000000000000001').passed, false);
});

test('stakedAtLeast: locked balance thresholds', () => {
  const s = snapshot({ account: { accountId: 'alice.testnet', amount: '10000000000000000000000000', locked: '5000000000000000000000000', storage_usage: 182, blockHeight: 100 } });
  assert.equal(stakedAtLeast(s, '5000000000000000000000000').passed, true);
  assert.equal(stakedAtLeast(s, '5000000000000000000000001').passed, false);
  assert.equal(stakedAtLeast(s, '0').passed, true);
  assert.equal(stakedAtLeast(snapshot(), '1').passed, false);
});

test('txCountInWindow: window edges are inclusive', () => {
  const atStart = tx({ hash: 'A'.repeat(43), blockTimestampNs: (NOW - 30n * DAY_NS).toString() });
  const beforeStart = tx({ hash: 'B'.repeat(43), blockTimestampNs: (NOW - 30n * DAY_NS - 1n).toString() });
  const atNow = tx({ hash: 'C'.repeat(43), blockTimestampNs: NOW.toString() });
  const afterNow = tx({ hash: 'D'.repeat(43), blockTimestampNs: (NOW + 1n).toString() });
  const s = snapshot({ txs: [atStart, beforeStart, atNow, afterNow] });
  const r = txCountInWindow(s, 30, NOW);
  assert.equal(r.value, 2); // atStart + atNow; beforeStart and afterNow excluded
  assert.equal(r.passed, true);
  assert.equal(r.threshold, 30);
});

test('txCountInWindow: failed txs excluded, empty list is zero', () => {
  const failed = tx({ hash: 'E'.repeat(43), status: 'Failure' });
  const ok = tx({ hash: 'F'.repeat(43), status: 'Success' });
  assert.equal(txCountInWindow(snapshot({ txs: [failed] }), 30, NOW).value, 0);
  assert.equal(txCountInWindow(snapshot({ txs: [failed] }), 30, NOW).passed, false);
  assert.equal(txCountInWindow(snapshot({ txs: [failed, ok] }), 30, NOW).value, 1);
  assert.equal(txCountInWindow(snapshot(), 30, NOW).value, 0);
  assert.equal(txCountInWindow(snapshot(), 30, NOW).passed, false);
});

test('volumeInWindow: sums transfers, excludes failures and non-transfers', () => {
  const in1 = tx({ hash: 'G'.repeat(43), senderId: 'alice.testnet', receiverId: 'bob.testnet', amountYocto: '2000000000000000000000000' });
  const in2 = tx({ hash: 'H'.repeat(43), senderId: 'carol.testnet', receiverId: 'alice.testnet', amountYocto: '3000000000000000000000000' });
  const failed = tx({ hash: 'I'.repeat(43), senderId: 'alice.testnet', receiverId: 'bob.testnet', amountYocto: '9000000000000000000000000', status: 'Failure' });
  const unrelated = tx({ hash: 'J'.repeat(43), senderId: 'carol.testnet', receiverId: 'dave.testnet', amountYocto: '8000000000000000000000000' });
  const s = snapshot({ txs: [in1, in2, failed, unrelated] });
  const r = volumeInWindow(s, 30, NOW);
  assert.equal(r.value, '5000000000000000000000000'); // 2 + 3 NEAR only
  assert.equal(r.passed, true);
});

test('volumeInWindow: self-transfer counted once, BigInt sums', () => {
  const self = tx({ hash: 'K'.repeat(43), senderId: 'alice.testnet', receiverId: 'alice.testnet', amountYocto: '1000000000000000000000000000000' });
  const r = volumeInWindow(snapshot({ txs: [self] }), 30, NOW);
  assert.equal(r.value, '1000000000000000000000000000000');
  // Two huge transfers must sum exactly, not round.
  const big1 = tx({ hash: 'L'.repeat(43), senderId: 'alice.testnet', amountYocto: '999999999999999999999999999999' });
  const big2 = tx({ hash: 'M'.repeat(43), senderId: 'alice.testnet', amountYocto: '1' });
  assert.equal(volumeInWindow(snapshot({ txs: [big1, big2] }), 30, NOW).value, '1000000000000000000000000000000');
  assert.equal(volumeInWindow(snapshot(), 30, NOW).value, '0');
  assert.equal(volumeInWindow(snapshot(), 30, NOW).passed, false);
});

test('noFailedTxsInWindow: counts failures in window only', () => {
  const failedIn = tx({ hash: 'N'.repeat(43), status: 'Failure' });
  const failedOld = tx({ hash: 'O'.repeat(43), status: 'Failure', blockTimestampNs: (NOW - 31n * DAY_NS).toString() });
  const ok = tx({ hash: 'P'.repeat(43), status: 'Success' });
  assert.deepEqual(noFailedTxsInWindow(snapshot({ txs: [failedIn] }), 30, NOW), { id: 'no_failed_txs_in_window', passed: false, value: 1, threshold: 30 });
  assert.equal(noFailedTxsInWindow(snapshot({ txs: [failedOld, ok] }), 30, NOW).passed, true);
  assert.equal(noFailedTxsInWindow(snapshot({ txs: [failedOld, ok] }), 30, NOW).value, 0);
  assert.equal(noFailedTxsInWindow(snapshot(), 30, NOW).passed, true);
});

test('evaluateClaims: only policy-named claims are evaluated', () => {
  const s = snapshot({ txs: [tx({ hash: 'Q'.repeat(43), senderId: 'alice.testnet', amountYocto: '1000000000000000000000000' })] });
  const full = evaluateClaims(s, {
    balanceAtLeastYocto: '10000000000000000000000000',
    stakedAtLeastYocto: '0',
    minTxCount: 1,
    txWindowDays: 30,
    minVolumeYocto: '1000000000000000000000000',
    volumeWindowDays: 30,
    noFailedWindowDays: 30,
  }, NOW);
  assert.equal(full.claims.length, 5);
  assert.equal(full.allPassed, true);

  const subset = evaluateClaims(s, { balanceAtLeastYocto: '1' }, NOW);
  assert.equal(subset.claims.length, 1);
  assert.equal(subset.claims[0].id, 'balance_at_least');

  const empty = evaluateClaims(s, {}, NOW);
  assert.deepEqual(empty, { claims: [], allPassed: true });
});

test('evaluateClaims: one failing claim fails the whole policy', () => {
  const s = snapshot();
  const r = evaluateClaims(s, { balanceAtLeastYocto: '10000000000000000000000000', minTxCount: 1, txWindowDays: 30 }, NOW);
  assert.equal(r.claims.find((c) => c.id === 'balance_at_least').passed, true);
  assert.equal(r.claims.find((c) => c.id === 'tx_count_in_window').passed, false);
  assert.equal(r.allPassed, false);
});

test('evaluateClaims: policy thresholds override standalone pass rules', () => {
  const s = snapshot({ txs: [tx({ hash: 'R'.repeat(43), senderId: 'alice.testnet', amountYocto: '1000000000000000000000000' })] });
  // Standalone txCountInWindow would pass (count 1 >= 1), but minTxCount 2 fails it.
  const r = evaluateClaims(s, { minTxCount: 2, txWindowDays: 30, minVolumeYocto: '2000000000000000000000000', volumeWindowDays: 30 }, NOW);
  assert.equal(r.claims.find((c) => c.id === 'tx_count_in_window').value, 1);
  assert.equal(r.claims.find((c) => c.id === 'tx_count_in_window').passed, false);
  assert.equal(r.claims.find((c) => c.id === 'volume_in_window').value, '1000000000000000000000000');
  assert.equal(r.claims.find((c) => c.id === 'volume_in_window').passed, false);
  assert.equal(r.allPassed, false);
});

test('evaluateClaims: half-specified windowed claim is a policy error, not a silent default', () => {
  const s = snapshot();
  assert.throws(() => evaluateClaims(s, { minTxCount: 1 }, NOW), /requires policy\.txWindowDays/);
  assert.throws(() => evaluateClaims(s, { minVolumeYocto: '1' }, NOW), /requires policy\.volumeWindowDays/);
  assert.throws(() => evaluateClaims(s, null, NOW), /policy must be an object/);
});

test('engine rejects malformed amounts and windows', () => {
  const s = snapshot();
  assert.throws(() => balanceAtLeast(s, '1.5'), /non-negative integer/);
  assert.throws(() => balanceAtLeast(s, '-1'), /non-negative integer/);
  assert.throws(() => txCountInWindow(s, -1, NOW), /non-negative integer number of days/);
  assert.throws(() => txCountInWindow(s, 1.5, NOW), /non-negative integer number of days/);
  assert.throws(() => balanceAtLeast({ account: { amount: 'abc', locked: '0' }, txs: [] }, '1'), /non-negative integer/);
});

test('aggregateBalanceAtLeast: sums balances across wallets', () => {
  const a = snapshot();
  const b = snapshot({ account: { accountId: 'bob.testnet', amount: '3000000000000000000000000', locked: '0', storage_usage: 182, blockHeight: 100 } });
  const r = evaluateClaims({ wallets: [a, b] }, { aggregateBalanceAtLeastYocto: '13000000000000000000000000' }, NOW);
  assert.equal(r.claims[0].id, 'aggregate_balance_at_least');
  assert.equal(r.claims[0].value, '13000000000000000000000000');
  assert.equal(r.claims[0].passed, true);
  assert.equal(evaluateClaims({ wallets: [a, b] }, { aggregateBalanceAtLeastYocto: '13000000000000000000000001' }, NOW).allPassed, false);
});

test('aggregate volume/count: union txs counted once, including transfers between own wallets', () => {
  const shared = tx({ hash: 'S'.repeat(43), senderId: 'alice.testnet', receiverId: 'bob.testnet', amountYocto: '2000000000000000000000000' });
  const a = snapshot({ txs: [shared] });
  const b = snapshot({ account: { accountId: 'bob.testnet', amount: '1000000000000000000000000', locked: '0', storage_usage: 182, blockHeight: 100 }, txs: [shared] });
  const r = evaluateClaims({ wallets: [a, b] }, { aggregateMinTxCount: 1, aggregateTxWindowDays: 30, aggregateMinVolumeYocto: '2000000000000000000000000', aggregateVolumeWindowDays: 30 }, NOW);
  assert.equal(r.claims.find((c) => c.id === 'aggregate_tx_count_in_window').value, 1);
  assert.equal(r.claims.find((c) => c.id === 'aggregate_volume_in_window').value, '2000000000000000000000000');
  assert.equal(r.allPassed, true);
});

test('sustained + time-weighted: min and mean of sampled sums', () => {
  const samples = (amounts) => amounts.map((amount, i) => ({ blockHeight: 90 + i, amount }));
  const a = snapshot({ balanceSamples: samples(['10000000000000000000000000', '9000000000000000000000000', '11000000000000000000000000']) });
  const r = evaluateClaims(a, { sustainedBalanceAtLeastYocto: '9000000000000000000000000', timeWeightedBalanceAtLeastYocto: '10000000000000000000000000' }, NOW);
  assert.equal(r.claims.find((c) => c.id === 'sustained_balance_at_least').value, '9000000000000000000000000');
  assert.equal(r.claims.find((c) => c.id === 'sustained_balance_at_least').passed, true);
  assert.equal(r.claims.find((c) => c.id === 'time_weighted_balance_at_least').value, '10000000000000000000000000');
  assert.equal(r.claims.find((c) => c.id === 'time_weighted_balance_at_least').passed, true);
  // A flash dip below the sustained threshold fails sustained but not the mean.
  assert.equal(evaluateClaims(a, { sustainedBalanceAtLeastYocto: '9500000000000000000000000' }, NOW).allPassed, false);
});

test('sustained claims without samples, or with misaligned samples, throw', () => {
  const a = snapshot();
  assert.throws(() => evaluateClaims(a, { sustainedBalanceAtLeastYocto: '1' }, NOW), /balanceSamples/);
  const b = snapshot({ balanceSamples: [{ blockHeight: 90, amount: '1000' }, { blockHeight: 95, amount: '1000' }] });
  const c = snapshot({ account: { accountId: 'carol.testnet', amount: '1000', locked: '0', storage_usage: 182, blockHeight: 100 }, balanceSamples: [{ blockHeight: 91, amount: '1000' }, { blockHeight: 95, amount: '1000' }] });
  assert.throws(() => evaluateClaims({ wallets: [b, c] }, { sustainedBalanceAtLeastYocto: '1' }, NOW), /block heights must match/);
});

test('evaluateClaims: old single-wallet policies evaluate exactly as before', () => {
  const s = snapshot({ txs: [tx({ amountYocto: '1500000000000000000000000' })] });
  const r = evaluateClaims(s, { balanceAtLeastYocto: '10000000000000000000000000', minTxCount: 1, txWindowDays: 30 }, NOW);
  assert.deepEqual(r.claims.map((c) => c.id), ['balance_at_least', 'tx_count_in_window']);
  assert.equal(r.allPassed, true);
  assert.throws(() => evaluateClaims({ wallets: [] }, {}, NOW), /at least one wallet/);
});
