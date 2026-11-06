// VeilProof portable credit score tests — pure, no network.
import test from 'node:test';
import assert from 'node:assert/strict';
import { computeScore, SCORE_VERSION, SCORE_MAX } from '../src/score.js';

const DAY_NS = 86400n * 1_000_000_000n;
const NOW = 1793958583519543793n;
const NEAR = 10n ** 24n;

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
    account: { accountId: 'alice.testnet', amount: (10n * NEAR).toString(), locked: '0', storage_usage: 182, blockHeight: 100 },
    txs: [],
    blockHeight: 100,
    dataHash: '0'.repeat(64),
    ...overrides,
  };
}

// Txs spread across three ISO weeks: now, now-8d, now-16d.
function spreadTxs() {
  return [0, 8, 16].map((days, i) =>
    tx({
      hash: String.fromCharCode(65 + i).repeat(43),
      amountYocto: (2n * NEAR).toString(),
      blockTimestampNs: (NOW - BigInt(days) * DAY_NS).toString(),
    }),
  );
}

test('score v2: strong profile with samples, spread activity, volume, no failures, staked', () => {
  const samples = [10n, 10n, 10n].map((n, i) => ({ blockHeight: 90 + i, amount: (n * NEAR).toString() }));
  const s = snapshot({
    account: { accountId: 'alice.testnet', amount: (10n * NEAR).toString(), locked: (NEAR).toString(), storage_usage: 182, blockHeight: 100 },
    txs: spreadTxs(),
    balanceSamples: samples,
  });
  const score = computeScore(s, { txWindowDays: 30, volumeWindowDays: 30, noFailedWindowDays: 30 }, NOW.toString());
  assert.equal(score.version, SCORE_VERSION);
  assert.equal(score.version, 'score-v2');
  // 350 sustained + 150 time-weighted + 90 activity (70 + 20 spread, 3 external txs over 3 weeks) + 30 diversity (1 outside counterparty: bob) + 90 volume (6 NEAR external) + 100 no_failed + 50 staked.
  assert.equal(score.value, 860);
  assert.equal(score.band, 'strong');
  assert.equal(score.components.find((c) => c.id === 'sustained_balance').points, 350);
  assert.equal(score.components.find((c) => c.id === 'time_weighted_balance').points, 150);
  assert.equal(score.components.find((c) => c.id === 'activity').points, 90);
  assert.equal(score.components.find((c) => c.id === 'counterparty_diversity').points, 30);
  assert.equal(score.components.find((c) => c.id === 'volume').points, 90);
  assert.equal(score.components.every((c) => c.measured), true);
});

test('score v1: the same profile recomputes exactly under its own rules', () => {
  const samples = [10n, 10n, 10n].map((n, i) => ({ blockHeight: 90 + i, amount: (n * NEAR).toString() }));
  const s = snapshot({
    account: { accountId: 'alice.testnet', amount: (10n * NEAR).toString(), locked: (NEAR).toString(), storage_usage: 182, blockHeight: 100 },
    txs: spreadTxs(),
    balanceSamples: samples,
  });
  const score = computeScore(s, { txWindowDays: 30, volumeWindowDays: 30, noFailedWindowDays: 30 }, NOW.toString(), 'score-v1');
  assert.equal(score.version, 'score-v1');
  // 300 sustained + 200 time-weighted + 120 activity (90 + 30 spread) + 130 volume (6 NEAR) + 100 no_failed + 50 staked.
  assert.equal(score.value, 900);
  assert.equal(score.band, 'strong');
  assert.equal(score.components.find((c) => c.id === 'activity').points, 120);
  assert.equal(score.components.find((c) => c.id === 'counterparty_diversity'), undefined);
});

test('score: unmeasured features score 0 and are flagged, thin band', () => {
  const s = snapshot();
  const score = computeScore(s, {}, NOW.toString());
  assert.equal(score.value, 0);
  assert.equal(score.band, 'thin');
  assert.equal(score.components.find((c) => c.id === 'sustained_balance').measured, false);
  assert.equal(score.components.find((c) => c.id === 'activity').measured, false);
  assert.equal(score.components.find((c) => c.id === 'staked').measured, true);
  assert.equal(score.components.find((c) => c.id === 'staked').points, 0);
});

test('score: flash deposit fails sustained but passes time-weighted partially', () => {
  const samples = [1n, 1n, 10n].map((n, i) => ({ blockHeight: 90 + i, amount: (n * NEAR).toString() }));
  const s = snapshot({ balanceSamples: samples });
  const score = computeScore(s, {}, NOW.toString());
  // v2: min 1 NEAR -> 230, mean 4 NEAR -> 100.
  assert.equal(score.components.find((c) => c.id === 'sustained_balance').points, 230);
  assert.equal(score.components.find((c) => c.id === 'time_weighted_balance').points, 100);
  // v1: min 1 NEAR -> 200, mean 4 NEAR -> 130.
  const v1 = computeScore(s, {}, NOW.toString(), 'score-v1');
  assert.equal(v1.components.find((c) => c.id === 'sustained_balance').points, 200);
  assert.equal(v1.components.find((c) => c.id === 'time_weighted_balance').points, 130);
});

test('score v2: burst activity without week spread gets no spread bonus; failed tx zeroes no_failed', () => {
  const burst = [0, 0, 0].map((_, i) =>
    tx({ hash: String.fromCharCode(66 + i).repeat(43), blockTimestampNs: NOW.toString() }),
  );
  const failed = tx({ hash: 'Z'.repeat(43), status: 'Failure' });
  const s = snapshot({ txs: [...burst, failed] });
  const score = computeScore(s, { txWindowDays: 30, noFailedWindowDays: 30 }, NOW.toString());
  assert.equal(score.components.find((c) => c.id === 'activity').points, 70);
  assert.equal(score.components.find((c) => c.id === 'counterparty_diversity').points, 30);
  assert.equal(score.components.find((c) => c.id === 'no_failed').points, 0);
});

test('score v1: the same burst scores 90 activity under the old weights', () => {
  const burst = [0, 0, 0].map((_, i) =>
    tx({ hash: String.fromCharCode(66 + i).repeat(43), blockTimestampNs: NOW.toString() }),
  );
  const failed = tx({ hash: 'Z'.repeat(43), status: 'Failure' });
  const s = snapshot({ txs: [...burst, failed] });
  const score = computeScore(s, { txWindowDays: 30, noFailedWindowDays: 30 }, NOW.toString(), 'score-v1');
  assert.equal(score.components.find((c) => c.id === 'activity').points, 90);
  assert.equal(score.components.find((c) => c.id === 'no_failed').points, 0);
});

test('score v2: wash txs between your own wallets add activity but no diversity', () => {
  // 5 txs, all between alice and bob (the bundle's own wallets):
  // activity counts them, diversity does not.
  const wash = [0, 1, 2, 3, 4].map((i) =>
    tx({ hash: String.fromCharCode(67 + i).repeat(43), senderId: 'alice.testnet', receiverId: 'bob.testnet', blockTimestampNs: NOW.toString() }),
  );
  const a = snapshot({ txs: wash });
  const b = snapshot({ account: { accountId: 'bob.testnet', amount: (5n * NEAR).toString(), locked: '0', storage_usage: 182, blockHeight: 100 }, txs: wash });
  const score = computeScore({ wallets: [a, b] }, { txWindowDays: 30 }, NOW.toString());
  assert.equal(score.components.find((c) => c.id === 'activity').points, 0);
  assert.equal(score.components.find((c) => c.id === 'counterparty_diversity').points, 0);
  // One real outside counterparty (carol) earns activity + diversity; the wash txs still earn nothing.
  const real = tx({ hash: 'R'.repeat(43), senderId: 'carol.testnet', receiverId: 'alice.testnet', blockTimestampNs: NOW.toString() });
  const a2 = snapshot({ txs: [...wash, real] });
  const withReal = computeScore({ wallets: [a2, b] }, { txWindowDays: 30 }, NOW.toString());
  assert.equal(withReal.components.find((c) => c.id === 'counterparty_diversity').points, 30);
  assert.equal(withReal.components.find((c) => c.id === 'activity').points, 30);
});

test('score v2: diversity tiers rise with distinct outside counterparties', () => {
  const mk = (n) =>
    Array.from({ length: n }, (_, i) =>
      tx({ hash: String.fromCharCode(65 + i).repeat(43), senderId: `counterparty${i}.testnet`, receiverId: 'alice.testnet', blockTimestampNs: NOW.toString() }),
    );
  const div = (n) => computeScore(snapshot({ txs: mk(n) }), { txWindowDays: 30 }, NOW.toString()).components.find((c) => c.id === 'counterparty_diversity').points;
  assert.equal(div(0), 0);
  assert.equal(div(1), 30);
  assert.equal(div(2), 60);
  assert.equal(div(5), 85);
  assert.equal(div(10), 100);
  assert.throws(() => computeScore(snapshot(), {}, NOW.toString(), 'score-v9'), /unknown version/);
});

test('score: multi-wallet sums balances and dedups shared txs', () => {
  const shared = tx({ hash: 'S'.repeat(43), senderId: 'alice.testnet', receiverId: 'bob.testnet', amountYocto: (2n * NEAR).toString() });
  const a = snapshot({ txs: [shared] });
  const b = snapshot({ account: { accountId: 'bob.testnet', amount: (5n * NEAR).toString(), locked: '0', storage_usage: 182, blockHeight: 100 }, txs: [shared] });
  const score = computeScore({ wallets: [a, b] }, { txWindowDays: 30, volumeWindowDays: 30 }, NOW.toString());
  // Aggregate balance 15 NEAR is not scored directly. The shared tx is
  // between the bundle's own wallets (internal), so under v2 it earns
  // nothing in activity, volume or diversity.
  assert.equal(score.components.find((c) => c.id === 'volume').points, 0);
  assert.equal(score.components.find((c) => c.id === 'activity').points, 0);
  assert.equal(score.components.find((c) => c.id === 'counterparty_diversity').points, 0);
  // Under v1 the same bundle scores 40 activity and 100 volume (2 NEAR counted once) and has no diversity component.
  const v1 = computeScore({ wallets: [a, b] }, { txWindowDays: 30, volumeWindowDays: 30 }, NOW.toString(), 'score-v1');
  assert.equal(v1.components.find((c) => c.id === 'activity').points, 40);
  assert.equal(v1.components.find((c) => c.id === 'volume').points, 100);
  assert.equal(v1.components.find((c) => c.id === 'counterparty_diversity'), undefined);
});

test('score: deterministic — same inputs, same score and components', () => {
  const s = snapshot({ txs: spreadTxs() });
  const a = computeScore(s, { txWindowDays: 30, volumeWindowDays: 30 }, NOW.toString());
  const b = computeScore(s, { txWindowDays: 30, volumeWindowDays: 30 }, NOW.toString());
  assert.deepEqual(a, b);
  assert.equal(SCORE_MAX, 1000);
});
