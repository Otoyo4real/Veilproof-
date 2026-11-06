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

test('score: strong profile with samples, spread activity, volume, no failures, staked', () => {
  const samples = [10n, 10n, 10n].map((n, i) => ({ blockHeight: 90 + i, amount: (n * NEAR).toString() }));
  const s = snapshot({
    account: { accountId: 'alice.testnet', amount: (10n * NEAR).toString(), locked: (NEAR).toString(), storage_usage: 182, blockHeight: 100 },
    txs: spreadTxs(),
    balanceSamples: samples,
  });
  const score = computeScore(s, { txWindowDays: 30, volumeWindowDays: 30, noFailedWindowDays: 30 }, NOW.toString());
  assert.equal(score.version, SCORE_VERSION);
  // 300 sustained + 200 time-weighted + 120 activity (90 + 30 spread) + 130 volume (6 NEAR) + 100 no_failed + 50 staked.
  assert.equal(score.value, 900);
  assert.equal(score.band, 'strong');
  assert.equal(score.components.find((c) => c.id === 'sustained_balance').points, 300);
  assert.equal(score.components.find((c) => c.id === 'activity').points, 120);
  assert.equal(score.components.every((c) => c.measured), true);
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
  assert.equal(score.components.find((c) => c.id === 'sustained_balance').points, 200);
  assert.equal(score.components.find((c) => c.id === 'time_weighted_balance').points, 130);
});

test('score: burst activity without week spread gets no spread bonus; failed tx zeroes no_failed', () => {
  const burst = [0, 0, 0].map((_, i) =>
    tx({ hash: String.fromCharCode(66 + i).repeat(43), blockTimestampNs: NOW.toString() }),
  );
  const failed = tx({ hash: 'Z'.repeat(43), status: 'Failure' });
  const s = snapshot({ txs: [...burst, failed] });
  const score = computeScore(s, { txWindowDays: 30, noFailedWindowDays: 30 }, NOW.toString());
  assert.equal(score.components.find((c) => c.id === 'activity').points, 90);
  assert.equal(score.components.find((c) => c.id === 'no_failed').points, 0);
});

test('score: multi-wallet sums balances and dedups shared txs', () => {
  const shared = tx({ hash: 'S'.repeat(43), senderId: 'alice.testnet', receiverId: 'bob.testnet', amountYocto: (2n * NEAR).toString() });
  const a = snapshot({ txs: [shared] });
  const b = snapshot({ account: { accountId: 'bob.testnet', amount: (5n * NEAR).toString(), locked: '0', storage_usage: 182, blockHeight: 100 }, txs: [shared] });
  const score = computeScore({ wallets: [a, b] }, { txWindowDays: 30, volumeWindowDays: 30 }, NOW.toString());
  // Aggregate balance 15 NEAR is not scored directly; volume counts the shared tx once (2 NEAR -> 100 pts).
  assert.equal(score.components.find((c) => c.id === 'volume').points, 100);
  assert.equal(score.components.find((c) => c.id === 'activity').points, 40);
});

test('score: deterministic — same inputs, same score and components', () => {
  const s = snapshot({ txs: spreadTxs() });
  const a = computeScore(s, { txWindowDays: 30, volumeWindowDays: 30 }, NOW.toString());
  const b = computeScore(s, { txWindowDays: 30, volumeWindowDays: 30 }, NOW.toString());
  assert.deepEqual(a, b);
  assert.equal(SCORE_MAX, 1000);
});
