// VeilProof sampling evidence tests — pure, no network (except the
// mocked-fetch test for sampleBalanceHistoryDetailed, which stubs
// globalThis.fetch inside the test file only and restores it after).
//
// These tests assert behaviour of the real engine — the sampling
// record shape, completeness, warnings, timestamps and limits —
// never a hardcoded score. The demo fixture uses the real committed
// demo disclosure, so the sampling record it asserts is the one the
// live demo claim carries.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describeSampling, WIDE_INTERVAL_BLOCKS, MIN_MEANINGFUL_SAMPLES, SAMPLING_LIMITATION } from '../src/sampling.js';
import { sampleBalanceHistoryDetailed } from '../src/onchain.js';

const NEAR = 10n ** 24n;
const DAY_NS = 86400n * 1_000_000_000n;
const NOW = 1793958583519543793n;

function snap(accountId, samples, txs = []) {
  return {
    account: { accountId, amount: (10n * NEAR).toString(), locked: '0', storage_usage: 182, blockHeight: 1000 },
    txs,
    blockHeight: 1000,
    dataHash: '0'.repeat(64),
    balanceSamples: samples,
    balanceSampleWindowHours: 1,
  };
}

function sample(height, near, tsNs = undefined) {
  const s = { blockHeight: height, amount: (BigInt(near) * NEAR).toString() };
  if (tsNs !== undefined) s.blockTimestampNs = tsNs.toString();
  return s;
}

function tx(overrides = {}) {
  return {
    hash: 'A'.repeat(43),
    senderId: 'alice.testnet',
    receiverId: 'bob.testnet',
    amountYocto: '0',
    status: 'Success',
    blockHeight: 500,
    blockTimestampNs: NOW.toString(),
    ...overrides,
  };
}

const DEMO_DISCLOSURE = JSON.parse(readFileSync(new URL('../public/demo-disclosure.json', import.meta.url), 'utf8'));

test('sampling: the real demo disclosure describes 4 rpc readings, interval 900, complete, no warning', () => {
  const bundle = { wallets: [DEMO_DISCLOSURE.snapshot, ...DEMO_DISCLOSURE.linked.map((l) => l.snapshot)] };
  const rec = describeSampling(bundle);
  assert.equal(rec.windowHours, 1);
  assert.equal(rec.intervalBlocks, 900);
  assert.equal(rec.sampleCount, 4);
  assert.equal(rec.oldestBlock, 276512600);
  assert.equal(rec.newestBlock, 276515300);
  assert.equal(rec.completeness, 'complete');
  assert.deepEqual(rec.missingHeights, []);
  assert.equal(rec.samplesRequested, 4);
  assert.equal(rec.wideIntervalWarning, null);
  assert.equal(rec.timestampSource, 'rpc');
  assert.equal(rec.sampleTimestamps.length, 4);
  assert.ok(rec.sampleTimestamps.every((t) => t.source === 'rpc' && typeof t.timestampNs === 'string'));
  // Primary ~11.148 NEAR + linked ~1.5 NEAR at every height.
  assert.equal(rec.lowestObservedSampledBalance, '12647996057936901200000000');
  assert.equal(rec.limitation, SAMPLING_LIMITATION);
});

test('sampling: wide interval warns (interval over the threshold)', () => {
  const s = snap('alice.testnet', [sample(100, 10), sample(5100, 10), sample(10100, 10), sample(15100, 10)]);
  const rec = describeSampling(s);
  assert.equal(rec.intervalBlocks, 5000);
  assert.ok(rec.intervalBlocks > WIDE_INTERVAL_BLOCKS);
  assert.equal(rec.wideIntervalWarning.reason, 'interval_too_wide');
  assert.ok(rec.wideIntervalWarning.message.length > 0);
  // A warning is not a failure: the record is still complete.
  assert.equal(rec.completeness, 'complete');
});

test('sampling: exactly at the wide-interval threshold does not warn', () => {
  const step = WIDE_INTERVAL_BLOCKS;
  const s = snap('alice.testnet', [sample(100, 10), sample(100 + step, 10), sample(100 + 2 * step, 10), sample(100 + 3 * step, 10)]);
  assert.equal(describeSampling(s).intervalBlocks, step);
  assert.equal(describeSampling(s).wideIntervalWarning, null);
});

test('sampling: too few samples warns even with a tight interval', () => {
  const s = snap('alice.testnet', [sample(100, 10), sample(200, 10)]);
  const rec = describeSampling(s);
  assert.equal(rec.sampleCount, 2);
  assert.ok(rec.sampleCount < MIN_MEANINGFUL_SAMPLES);
  assert.equal(rec.wideIntervalWarning.reason, 'too_few_samples');
});

test('sampling: too few AND too wide reports both', () => {
  const s = snap('alice.testnet', [sample(100, 10), sample(100 + WIDE_INTERVAL_BLOCKS + 1, 10)]);
  assert.equal(describeSampling(s).wideIntervalWarning.reason, 'both');
});

test('sampling: a missing middle height is inferred from the grid and flagged partial', () => {
  const s = snap('alice.testnet', [sample(100, 10), sample(300, 8), sample(400, 10)]);
  const rec = describeSampling(s);
  assert.deepEqual(rec.missingHeights, [200]);
  assert.equal(rec.completeness, 'partial');
  assert.equal(rec.sampleCount, 3);
  // The lowest is the minimum over the heights that exist (8 NEAR at
  // height 300); the missing height contributes nothing.
  assert.equal(rec.lowestObservedSampledBalance, (8n * NEAR).toString());
});

test('sampling: fewer readings than requested is partial even with no grid gap', () => {
  const s = snap('alice.testnet', [sample(100, 10), sample(200, 10), sample(300, 10)]);
  const rec = describeSampling(s, { samplesRequested: 4 });
  assert.deepEqual(rec.missingHeights, []);
  assert.equal(rec.completeness, 'partial');
  assert.equal(rec.samplesRequested, 4);
});

test('sampling: a height present on one wallet but not the other is missing, and the sums skip it', () => {
  const a = snap('alice.testnet', [sample(100, 10), sample(200, 10), sample(300, 10)]);
  const b = snap('alice2.testnet', [sample(100, 5), sample(200, 5)]);
  const rec = describeSampling({ wallets: [a, b] });
  assert.deepEqual(rec.missingHeights, [300]);
  assert.equal(rec.completeness, 'partial');
  assert.equal(rec.sampleCount, 2);
  // Summed over complete heights only: 15 NEAR at 100 and 200. The
  // 300 height (10 NEAR on one wallet, unknown on the other) is not
  // summed — a sum over a missed height would understate the balance.
  assert.equal(rec.lowestObservedSampledBalance, (15n * NEAR).toString());
});

test('sampling: funds moved between sample points show in the lowest reading; a dip between samples does not', () => {
  // The balance left and came back between the readings: the samples
  // only ever saw 10 NEAR, so the lowest observed is 10 NEAR — and
  // the limitation says so in plain language.
  const moved = snap('alice.testnet', [sample(100, 10), sample(200, 10)]);
  const rec = describeSampling(moved);
  assert.equal(rec.lowestObservedSampledBalance, (10n * NEAR).toString());
  assert.ok(rec.limitation.includes('do not prove the balance was held continuously'));
  // When the dip lands ON a sample point, it is visible.
  const dipped = snap('alice.testnet', [sample(100, 10), sample(200, 0), sample(300, 10)]);
  assert.equal(describeSampling(dipped).lowestObservedSampledBalance, '0');
});

test('sampling: no samples is none, with nulls and no warning', () => {
  const rec = describeSampling(snap('alice.testnet', []));
  assert.equal(rec.completeness, 'none');
  assert.equal(rec.sampleCount, 0);
  assert.equal(rec.intervalBlocks, null);
  assert.equal(rec.oldestBlock, null);
  assert.equal(rec.newestBlock, null);
  assert.equal(rec.lowestObservedSampledBalance, null);
  assert.equal(rec.sampleTimestamps, null);
  assert.equal(rec.wideIntervalWarning, null);
});

test('sampling: a single sample has no interval and warns for too few', () => {
  const rec = describeSampling(snap('alice.testnet', [sample(100, 10)]), { samplesRequested: 1 });
  assert.equal(rec.sampleCount, 1);
  assert.equal(rec.intervalBlocks, null);
  assert.equal(rec.completeness, 'complete');
  assert.equal(rec.wideIntervalWarning.reason, 'too_few_samples');
});

test('sampling: timestamps are estimated from the newest disclosed tx anchor when the chain gave none', () => {
  const anchorTx = tx({ blockHeight: 150, blockTimestampNs: (NOW - 10n * DAY_NS).toString() });
  const s = snap('alice.testnet', [sample(100, 10), sample(200, 10), sample(300, 10)], [anchorTx]);
  const rec = describeSampling(s);
  assert.equal(rec.timestampSource, 'estimated');
  assert.equal(rec.sampleTimestamps.length, 3);
  assert.ok(rec.sampleTimestamps.every((t) => t.source === 'estimated'));
  // Anchor at height 150; a sample 150 blocks later is 150 s later.
  const at300 = rec.sampleTimestamps.find((t) => t.blockHeight === 300);
  assert.equal(at300.timestampNs, (NOW - 10n * DAY_NS + 150n * 1_000_000_000n).toString());
});

test('sampling: with no stored timestamps and no tx anchor, times are unavailable', () => {
  const rec = describeSampling(snap('alice.testnet', [sample(100, 10), sample(200, 10), sample(300, 10), sample(400, 10)]));
  assert.equal(rec.timestampSource, 'unavailable');
  assert.equal(rec.sampleTimestamps, null);
});

test('sampling: a stored timestamp on any wallet wins over the estimate for that height', () => {
  const a = snap('alice.testnet', [sample(100, 10, NOW - 2n * DAY_NS), sample(200, 10)]);
  const b = snap('alice2.testnet', [sample(100, 5), sample(200, 5)]);
  const anchorTx = tx({ blockHeight: 150, blockTimestampNs: (NOW - 10n * DAY_NS).toString(), hash: 'B'.repeat(43) });
  a.txs = [anchorTx];
  const rec = describeSampling({ wallets: [a, b] });
  assert.equal(rec.timestampSource, 'estimated');
  assert.equal(rec.sampleTimestamps.find((t) => t.blockHeight === 100).source, 'rpc');
  assert.equal(rec.sampleTimestamps.find((t) => t.blockHeight === 200).source, 'estimated');
});

test('sampling: yocto amounts keep full precision (no float rounding)', () => {
  // 10 NEAR + 1 yocto: a float would round this to exactly 10 NEAR.
  const oneYoctoOver = (10n * NEAR + 1n).toString();
  const s = snap('alice.testnet', [
    { blockHeight: 100, amount: oneYoctoOver },
    { blockHeight: 200, amount: (10n * NEAR).toString() },
    { blockHeight: 300, amount: (10n * NEAR).toString() },
    { blockHeight: 400, amount: (10n * NEAR).toString() },
  ]);
  const rec = describeSampling(s);
  assert.equal(rec.lowestObservedSampledBalance, (10n * NEAR).toString());
  // And a 1-yocto sample is a real minimum, not zero.
  const dust = snap('alice.testnet', [
    { blockHeight: 100, amount: '1' },
    { blockHeight: 200, amount: (10n * NEAR).toString() },
    { blockHeight: 300, amount: (10n * NEAR).toString() },
    { blockHeight: 400, amount: (10n * NEAR).toString() },
  ]);
  assert.equal(describeSampling(dust).lowestObservedSampledBalance, '1');
});

test('sampling: malformed snapshots throw instead of producing a record', () => {
  assert.throws(() => describeSampling(snap('alice.testnet', [{ blockHeight: 100, amount: '-5' }])), /non-negative integer/);
  assert.throws(() => describeSampling(snap('alice.testnet', [{ blockHeight: 100, amount: 'not-a-number' }])), /non-negative integer/);
  assert.throws(() => describeSampling(snap('alice.testnet', [{ blockHeight: 100.5, amount: '1' }])), /non-negative integer/);
  assert.throws(() => describeSampling(snap('alice.testnet', [sample(100, 10), sample(100, 9)])), /duplicate balance sample/);
  assert.throws(() => describeSampling(null), /must be an object/);
  assert.throws(() => describeSampling([]), /must be an object/);
});

test('sampling: per-wallet record is the wallet alone (no cross-wallet sum)', () => {
  const a = snap('alice.testnet', [sample(100, 10), sample(200, 9), sample(300, 10), sample(400, 10)]);
  const rec = describeSampling(a, { samplesRequested: 4 });
  assert.equal(rec.lowestObservedSampledBalance, (9n * NEAR).toString());
  assert.equal(rec.completeness, 'complete');
});

// --- sampleBalanceHistoryDetailed: hard failures become missing
// heights; a hard failure only when NOTHING could be read. The fetch
// stub lives in this file only and is restored after each test.
function stubFetch(handler) {
  const original = globalThis.fetch;
  globalThis.fetch = handler;
  return () => { globalThis.fetch = original; };
}

test('sampleBalanceHistoryDetailed: an unservable height is recorded missing, the rest still return', async () => {
  const restore = stubFetch(async (_url, { body }) => {
    const { method, params } = JSON.parse(body);
    if (method === 'query' && params.block_id === 200) {
      return { ok: true, json: async () => ({ jsonrpc: '2.0', error: { name: 'HANDLER_ERROR', message: 'account not found at height' } }) };
    }
    if (method === 'query') {
      return { ok: true, json: async () => ({ jsonrpc: '2.0', result: { amount: (10n * NEAR).toString() } }) };
    }
    if (method === 'block') {
      return { ok: true, json: async () => ({ jsonrpc: '2.0', result: { header: { timestamp_nanosec: NOW.toString() } } }) };
    }
    throw new Error(`unexpected method ${method}`);
  });
  try {
    const out = await sampleBalanceHistoryDetailed('alice.testnet', { windowHours: 1, samples: 4, heights: [100, 200, 300, 400] });
    assert.deepEqual(out.missingHeights, [200]);
    assert.deepEqual(out.requestedHeights, [100, 200, 300, 400]);
    assert.equal(out.samplesRequested, 4);
    assert.deepEqual(out.samples.map((s) => s.blockHeight), [100, 300, 400]);
    assert.ok(out.samples.every((s) => s.blockTimestampNs === NOW.toString()));
    // The gap survives into the sampling record as partial.
    const s = snap('alice.testnet', out.samples);
    const rec = describeSampling(s, { samplesRequested: out.samplesRequested, missingHeights: out.missingHeights });
    assert.equal(rec.completeness, 'partial');
    assert.deepEqual(rec.missingHeights, [200]);
  } finally {
    restore();
  }
});

test('sampleBalanceHistoryDetailed: all heights unservable is still a hard failure', async () => {
  const restore = stubFetch(async () => ({
    ok: true,
    json: async () => ({ jsonrpc: '2.0', error: { name: 'HANDLER_ERROR', message: 'no such account' } }),
  }));
  try {
    await assert.rejects(
      () => sampleBalanceHistoryDetailed('alice.testnet', { windowHours: 1, samples: 4, heights: [100, 200, 300, 400] }),
      /no balance samples could be read/,
    );
  } finally {
    restore();
  }
});
