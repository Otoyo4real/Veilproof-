// VeilProof score manipulation-detection tests — pure, no network.
//
// These tests assert behaviour of the real engine — which patterns
// raise which flags, at which severity, and how counterparties are
// labelled — never a hardcoded score. Where points matter, the test
// compares two scores against each other (flags must not change
// points), not against a literal number.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { computeScore } from '../src/score.js';
import {
  SCORE_DISCLAIMER,
  detectRiskFlags,
  labelCounterparties,
  counterpartySummary,
} from '../src/manipulation.js';

const NEAR = 10n ** 24n;
const DAY_NS = 86400n * 1_000_000_000n;
const NOW = 1793958583519543793n;
const WINDOWS = { txWindowDays: 30, volumeWindowDays: 30, noFailedWindowDays: 30 };

let hashCounter = 0;
// Exact decimal NEAR -> yocto (no float rounding: '1.25' is 1.25 NEAR,
// not 1.3).
function y(nearStr) {
  const [whole, frac = ''] = String(nearStr).split('.');
  return BigInt(whole) * NEAR + BigInt((frac + '0'.repeat(24)).slice(0, 24));
}
function tx(senderId, receiverId, near, overrides = {}) {
  hashCounter += 1;
  return {
    hash: `H${String(hashCounter).padStart(42, '0')}`,
    senderId,
    receiverId,
    amountYocto: y(near).toString(),
    status: 'Success',
    blockHeight: 500,
    blockTimestampNs: NOW.toString(),
    ...overrides,
  };
}

function snap(accountId, txs = []) {
  return {
    account: { accountId, amount: (10n * NEAR).toString(), locked: '0', storage_usage: 182, blockHeight: 1000 },
    txs,
    blockHeight: 1000,
    dataHash: '0'.repeat(64),
  };
}

function bundleOf(...snaps) {
  return { wallets: snaps };
}

function scoreOf(bundle) {
  return computeScore(bundle, WINDOWS, NOW.toString());
}

function flagTypes(score) {
  return (score.riskFlags || []).map((f) => f.type);
}

test('manipulation: circular flow flags when most of the value comes back', () => {
  const s = snap('alice.testnet', [
    tx('alice.testnet', 'mallory.testnet', 5),
    tx('mallory.testnet', 'alice.testnet', 4),
  ]);
  const { flags, suspicious } = detectRiskFlags(s, { txWindowDays: 30, nowNs: NOW.toString() });
  const flow = flags.find((f) => f.type === 'circular_flow');
  assert.ok(flow, 'expected a circular_flow flag');
  assert.equal(flow.severity, 'high'); // 4 NEAR returned, at the 1 NEAR high bar
  assert.ok(flow.detail.includes('5 NEAR out, 4 NEAR back (80% returned)'));
  assert.ok(suspicious.has('mallory.testnet'));
  assert.ok(!suspicious.has('alice.testnet'));
});

test('manipulation: funding-dominated flow does NOT flag (demo-like 48% return)', () => {
  // The demo's own shape: 0.6 NEAR out, 1.25 NEAR in from the same
  // outside account — funding, not a round trip.
  const s = snap('alice.testnet', [
    tx('alice.testnet', 'funder.testnet', 0.6),
    tx('funder.testnet', 'alice.testnet', 1.25),
  ]);
  const { flags } = detectRiskFlags(s, { txWindowDays: 30, nowNs: NOW.toString() });
  assert.equal(flags.find((f) => f.type === 'circular_flow'), undefined);
});

test('manipulation: circular flow boundary — exactly 50% returned flags, just below does not', () => {
  const atHalf = snap('alice.testnet', [
    tx('alice.testnet', 'a.testnet', 2),
    tx('a.testnet', 'alice.testnet', 1),
  ]);
  assert.ok(detectRiskFlags(atHalf, { txWindowDays: 30, nowNs: NOW.toString() }).flags.some((f) => f.type === 'circular_flow'));
  const belowHalf = snap('alice.testnet', [
    tx('alice.testnet', 'b.testnet', 2),
    tx('b.testnet', 'alice.testnet', 0.9),
  ]);
  assert.equal(detectRiskFlags(belowHalf, { txWindowDays: 30, nowNs: NOW.toString() }).flags.find((f) => f.type === 'circular_flow'), undefined);
});

test('manipulation: circular flow boundary — under 0.1 NEAR never flags, even at 100% return', () => {
  const s = snap('alice.testnet', [
    tx('alice.testnet', 'c.testnet', 0.05),
    tx('c.testnet', 'alice.testnet', 0.05),
  ]);
  assert.equal(detectRiskFlags(s, { txWindowDays: 30, nowNs: NOW.toString() }).flags.find((f) => f.type === 'circular_flow'), undefined);
  const atMin = snap('alice.testnet', [
    tx('alice.testnet', 'd.testnet', 0.1),
    tx('d.testnet', 'alice.testnet', 0.1),
  ]);
  assert.ok(detectRiskFlags(atMin, { txWindowDays: 30, nowNs: NOW.toString() }).flags.some((f) => f.type === 'circular_flow'));
});

test('manipulation: a 3-hop chain flags as circular_chain; a 2-cycle does not', () => {
  // The loop alice -> x -> y -> alice is visible because x is a
  // linked bundle wallet (its x -> y hop is in x's snapshot). So x is
  // 'own' and only the outside hop y is suspicious — the chain flag
  // is about the loop, the suspicious label is about who is outside.
  const chain = bundleOf(snap('alice.testnet', [
    tx('alice.testnet', 'x.testnet', 0.5),
    tx('y.testnet', 'alice.testnet', 0.5),
  ]), snap('x.testnet', [
    tx('x.testnet', 'y.testnet', 0.5),
  ]));
  // The union of both wallets' txs is the full loop alice -> x -> y -> alice.
  const found = detectRiskFlags(chain, { txWindowDays: 30, nowNs: NOW.toString() });
  const loop = found.flags.find((f) => f.type === 'circular_chain');
  assert.ok(loop, 'expected a circular_chain flag');
  assert.equal(loop.severity, 'medium'); // 0.5 NEAR legs, under the 1 NEAR high bar
  assert.ok(loop.detail.includes('3-hop'));
  assert.ok(found.suspicious.has('y.testnet'));
  assert.ok(!found.suspicious.has('x.testnet'), 'x is a bundle wallet, so it is own, not suspicious');

  const twoCycle = snap('alice.testnet', [
    tx('alice.testnet', 'z.testnet', 1),
    tx('z.testnet', 'alice.testnet', 1),
  ]);
  const two = detectRiskFlags(twoCycle, { txWindowDays: 30, nowNs: NOW.toString() });
  assert.equal(two.flags.find((f) => f.type === 'circular_chain'), undefined);
  assert.ok(two.flags.some((f) => f.type === 'circular_flow'), 'a 2-cycle is circular_flow, not a chain');
});

test('manipulation: one outside account funding two bundle wallets is a shared funder', () => {
  const b = bundleOf(
    snap('alice.testnet', [tx('funder.testnet', 'alice.testnet', 1)]),
    snap('alice2.testnet', [tx('funder.testnet', 'alice2.testnet', 1)]),
  );
  const { flags, suspicious } = detectRiskFlags(b, { txWindowDays: 30, nowNs: NOW.toString() });
  const shared = flags.find((f) => f.type === 'shared_funder');
  assert.ok(shared);
  assert.equal(shared.severity, 'medium');
  assert.ok(shared.detail.includes('2 wallets'));
  assert.ok(suspicious.has('funder.testnet'));
  // One funder, one wallet: no flag.
  const single = snap('alice.testnet', [tx('funder.testnet', 'alice.testnet', 1)]);
  assert.equal(detectRiskFlags(single, { txWindowDays: 30, nowNs: NOW.toString() }).flags.find((f) => f.type === 'shared_funder'), undefined);
});

test('manipulation: concentration boundary — exactly 80% flags, below does not', () => {
  const at80 = snap('alice.testnet', [
    tx('alice.testnet', 'top.testnet', 1),
    tx('alice.testnet', 'top.testnet', 1),
    tx('alice.testnet', 'top.testnet', 1),
    tx('alice.testnet', 'top.testnet', 1),
    tx('alice.testnet', 'other.testnet', 1),
  ]);
  const found = detectRiskFlags(at80, { txWindowDays: 30, nowNs: NOW.toString() });
  const conc = found.flags.find((f) => f.type === 'concentrated_counterparty');
  assert.ok(conc);
  assert.equal(conc.severity, 'medium');
  assert.ok(conc.detail.includes('80% of external transactions'));
  assert.ok(found.suspicious.has('top.testnet'));

  const below = snap('alice.testnet', [
    tx('alice.testnet', 'top.testnet', 1),
    tx('alice.testnet', 'top.testnet', 1),
    tx('alice.testnet', 'top.testnet', 1),
    tx('alice.testnet', 'other.testnet', 1),
    tx('alice.testnet', 'third.testnet', 1),
  ]);
  assert.equal(detectRiskFlags(below, { txWindowDays: 30, nowNs: NOW.toString() }).flags.find((f) => f.type === 'concentrated_counterparty'), undefined);
});

test('manipulation: repeated transfers — 3 same pair+amount flags, 2 does not, 5 is high', () => {
  const three = snap('alice.testnet', [
    tx('alice.testnet', 'bob.testnet', 1),
    tx('alice.testnet', 'bob.testnet', 1),
    tx('alice.testnet', 'bob.testnet', 1),
  ]);
  const found = detectRiskFlags(three, { txWindowDays: 30, nowNs: NOW.toString() });
  const rep = found.flags.find((f) => f.type === 'repeated_transfers');
  assert.ok(rep);
  assert.equal(rep.severity, 'medium');
  assert.ok(rep.detail.includes('3 times'));
  assert.ok(found.suspicious.has('bob.testnet'));

  const two = snap('alice.testnet', [
    tx('alice.testnet', 'bob.testnet', 1),
    tx('alice.testnet', 'bob.testnet', 1),
  ]);
  assert.equal(detectRiskFlags(two, { txWindowDays: 30, nowNs: NOW.toString() }).flags.find((f) => f.type === 'repeated_transfers'), undefined);

  const five = snap('alice.testnet', Array.from({ length: 5 }, () => tx('alice.testnet', 'bob.testnet', 1)));
  assert.equal(detectRiskFlags(five, { txWindowDays: 30, nowNs: NOW.toString() }).flags.find((f) => f.type === 'repeated_transfers').severity, 'high');

  // Same pair, different amounts: no repeat.
  const varied = snap('alice.testnet', [
    tx('alice.testnet', 'bob.testnet', 1),
    tx('alice.testnet', 'bob.testnet', 2),
    tx('alice.testnet', 'bob.testnet', 3),
  ]);
  assert.equal(detectRiskFlags(varied, { txWindowDays: 30, nowNs: NOW.toString() }).flags.find((f) => f.type === 'repeated_transfers'), undefined);
});

test('manipulation: duplicate tx hashes listed twice collapse to one (no phantom repeat)', () => {
  // The same transfer appears in both wallets' tx lists, as a real
  // internal transfer does. The union dedups by hash, so it counts
  // once — three listings of ONE hash are not three transfers.
  const shared = tx('alice.testnet', 'alice2.testnet', 1, { hash: 'D'.repeat(43) });
  const b = bundleOf(snap('alice.testnet', [shared]), snap('alice2.testnet', [shared, shared]));
  const { flags } = detectRiskFlags(b, { txWindowDays: 30, nowNs: NOW.toString() });
  assert.equal(flags.find((f) => f.type === 'repeated_transfers'), undefined);
  assert.ok(flags.some((f) => f.type === 'internal_transfers'));
});

test('manipulation: internal transfers are a low informational flag and earn nothing', () => {
  const internal = bundleOf(
    snap('alice.testnet', [tx('alice.testnet', 'alice2.testnet', 5)]),
    snap('alice2.testnet', []),
  );
  const score = scoreOf(internal);
  const flag = score.riskFlags.find((f) => f.type === 'internal_transfers');
  assert.ok(flag);
  assert.equal(flag.severity, 'low');
  const empty = scoreOf(bundleOf(snap('alice.testnet', []), snap('alice2.testnet', [])));
  // Same components as a bundle with no txs at all: internal moves
  // earn no activity, volume or diversity points.
  assert.deepEqual(score.components, empty.components);
  assert.equal(score.components.find((c) => c.id === 'counterparty_diversity').points, 0);
});

test('manipulation: counterparties are own, suspicious, or unknown — never assumed independent', () => {
  const b = bundleOf(snap('alice.testnet', [
    tx('alice.testnet', 'bob.testnet', 1),
    tx('alice.testnet', 'mallory.testnet', 5),
    tx('mallory.testnet', 'alice.testnet', 4),
    tx('alice.testnet', 'alice2.testnet', 1),
  ]), snap('alice2.testnet', []));
  const labels = labelCounterparties(b, { txWindowDays: 30, nowNs: NOW.toString() });
  const byAccount = new Map(labels.map((l) => [l.account, l.label]));
  assert.equal(byAccount.get('alice.testnet'), 'own');
  assert.equal(byAccount.get('alice2.testnet'), 'own');
  assert.equal(byAccount.get('bob.testnet'), 'unknown');
  assert.equal(byAccount.get('mallory.testnet'), 'suspicious');
  assert.deepEqual(counterpartySummary(labels), { own: 2, unknown: 1, suspicious: 1 });
  // No window assessed: no labels at all, not a guess.
  assert.deepEqual(labelCounterparties(b, {}), []);
});

test('manipulation: the score carries the disclaimer, and it says what the score is not', () => {
  const score = scoreOf(snap('alice.testnet', [tx('alice.testnet', 'bob.testnet', 1)]));
  assert.equal(score.disclaimer, SCORE_DISCLAIMER);
  assert.ok(score.disclaimer.includes('not a guarantee of repayment'));
  assert.ok(score.disclaimer.includes('identity'));
  assert.ok(score.disclaimer.includes('beneficial ownership'));
  assert.ok(score.disclaimer.includes('creditworthiness'));
  assert.ok(score.disclaimer.includes('observable onchain financial activity only'));
});

test('manipulation: flags do not change points (flag-only diversity rule)', () => {
  // Same 4 external txs, same 3 distinct counterparties, same 4 NEAR
  // volume, same week. A has a circular return (flagged); B replaces
  // the return with a second send (not flagged). Points must match
  // exactly — the flag is a warning, not a discount.
  const flagged = snap('alice.testnet', [
    tx('alice.testnet', 'bob.testnet', 1),
    tx('alice.testnet', 'carol.testnet', 1),
    tx('alice.testnet', 'mallory.testnet', 1),
    tx('mallory.testnet', 'alice.testnet', 1),
  ]);
  const clean = snap('alice.testnet', [
    tx('alice.testnet', 'bob.testnet', 1),
    tx('alice.testnet', 'carol.testnet', 1),
    tx('alice.testnet', 'mallory.testnet', 1),
    tx('alice.testnet', 'mallory.testnet', 1),
  ]);
  const a = scoreOf(flagged);
  const b = scoreOf(clean);
  assert.ok(a.riskFlags.some((f) => f.type === 'circular_flow'), 'A must carry the circular flag');
  assert.equal(b.riskFlags.find((f) => f.type === 'circular_flow'), undefined);
  assert.deepEqual(a.components, b.components);
  assert.equal(a.value, b.value);
  // Diversity still counts the flagged counterparty (flagged, not
  // discounted): 3 distinct outside accounts in both.
  assert.equal(a.components.find((c) => c.id === 'counterparty_diversity').points, b.components.find((c) => c.id === 'counterparty_diversity').points);
});

test('manipulation: the real demo bundle carries exactly the two known flags, and no circular flow', () => {
  const disclosure = JSON.parse(readFileSync(new URL('../public/demo-disclosure.json', import.meta.url), 'utf8'));
  const bundle = bundleOf(disclosure.snapshot, ...disclosure.linked.map((l) => l.snapshot));
  // Assessed as of the demo's publish time (the onchain created_at):
  // the demo txs are all just before it, inside the 30-day windows.
  // A wall-clock now would age the demo out of its windows.
  const score = computeScore(bundle, WINDOWS, '1793985812800431548');
  assert.deepEqual(flagTypes(score).sort(), ['concentrated_counterparty', 'internal_transfers']);
  assert.equal(score.riskFlags.find((f) => f.type === 'concentrated_counterparty').severity, 'medium');
  assert.equal(score.riskFlags.find((f) => f.type === 'internal_transfers').severity, 'low');
  assert.deepEqual(score.counterpartySummary, { own: 2, unknown: 0, suspicious: 1 });
  const labels = new Map(score.counterpartyLabels.map((l) => [l.account, l.label]));
  assert.equal(labels.get('veilproof.testnet'), 'suspicious');
  assert.equal(labels.get('veilproof-demo.testnet'), 'own');
  assert.equal(labels.get('demo2.veilproof.testnet'), 'own');
});

test('manipulation: failed and out-of-window txs do not trigger flags', () => {
  const s = snap('alice.testnet', [
    tx('alice.testnet', 'mallory.testnet', 5, { status: 'Failure' }),
    tx('mallory.testnet', 'alice.testnet', 4, { status: 'Failure' }),
    tx('alice.testnet', 'mallory.testnet', 5, { blockTimestampNs: (NOW - 40n * DAY_NS).toString() }),
    tx('mallory.testnet', 'alice.testnet', 4, { blockTimestampNs: (NOW - 40n * DAY_NS).toString() }),
  ]);
  const { flags } = detectRiskFlags(s, { txWindowDays: 30, nowNs: NOW.toString() });
  assert.deepEqual(flags, []);
});

test('manipulation: no window assessed means no flags and no labels (score still computes)', () => {
  const s = snap('alice.testnet', [
    tx('alice.testnet', 'mallory.testnet', 5),
    tx('mallory.testnet', 'alice.testnet', 4),
  ]);
  const score = computeScore(s, {}, NOW.toString());
  assert.deepEqual(score.riskFlags, []);
  assert.deepEqual(score.counterpartyLabels, []);
  assert.deepEqual(score.counterpartySummary, { own: 0, unknown: 0, suspicious: 0 });
  assert.equal(score.disclaimer, SCORE_DISCLAIMER);
});

test('manipulation: v1 scores also carry flags and the disclaimer (points unchanged)', () => {
  const s = snap('alice.testnet', [
    tx('alice.testnet', 'mallory.testnet', 5),
    tx('mallory.testnet', 'alice.testnet', 4),
  ]);
  const v1 = computeScore(s, WINDOWS, NOW.toString(), 'score-v1');
  const v2 = computeScore(s, WINDOWS, NOW.toString(), 'score-v2');
  assert.equal(v1.version, 'score-v1');
  assert.ok(v1.riskFlags.some((f) => f.type === 'circular_flow'));
  assert.equal(v1.disclaimer, SCORE_DISCLAIMER);
  assert.deepEqual(v1.riskFlags, v2.riskFlags);
  assert.deepEqual(v1.counterpartyLabels, v2.counterpartyLabels);
});
