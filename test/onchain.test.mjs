// VeilProof onchain tests — LIVE against NEAR testnet RPC.
// These need network and are slower than the pure engine tests.
// The made-up-hash test is the slowest: the node waits ~10s per lookup
// before answering NOT_OBSERVED, and verifyTx tries two endpoints.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  getAccount,
  verifyTx,
  fetchAccountSnapshot,
  computeDataHash,
  computeSampleHeights,
  sampleBalanceHistory,
} from '../src/onchain.js';

// The demo wallet was funded with 10 NEAR at creation, then the demo
// history in demo/history.json moved a net +0.65 NEAR into it (in: 1 +
// 0.25, out: 0.5 + 0.1) minus gas on its two outgoing transfers. The
// balance is therefore expected in [funding + net - gas allowance,
// funding + net], never an exact hardcoded value: gas varies, and the
// history file is the source of truth if it grows.
const DEMO_ACCOUNT = 'veilproof-demo.testnet';
const DEMO_HISTORY = JSON.parse(readFileSync(new URL('../demo/history.json', import.meta.url), 'utf8'));
const YOCTO_PER_NEAR = 10n ** 24n;
const GAS_ALLOWANCE_YOCTO = 5n * 10n ** 22n; // 0.05 NEAR — far above gas for a few simple transfers
function nearToYocto(nearStr) {
  const [whole, frac = ''] = nearStr.split('.');
  return BigInt(whole) * YOCTO_PER_NEAR + BigInt((frac + '0'.repeat(24)).slice(0, 24));
}
const DEMO_NET_YOCTO = DEMO_HISTORY.transfers.reduce((net, t) => {
  if (t.receiverId === DEMO_ACCOUNT) return net + nearToYocto(t.amountNear);
  if (t.senderId === DEMO_ACCOUNT) return net - nearToYocto(t.amountNear);
  return net;
}, 0n);
const DEMO_FUNDING_YOCTO = 10n * YOCTO_PER_NEAR;
function assertDemoBalance(amountYocto) {
  const amount = BigInt(amountYocto);
  assert.ok(amount <= DEMO_FUNDING_YOCTO + DEMO_NET_YOCTO,
    `demo balance ${amount} exceeds funding + recorded net transfers`);
  assert.ok(amount >= DEMO_FUNDING_YOCTO + DEMO_NET_YOCTO - GAS_ALLOWANCE_YOCTO,
    `demo balance ${amount} is below funding + recorded net transfers minus gas allowance`);
}

// A real testnet tx observed 2026-11-06 (btc-relayer -> btc-client-v4,
// FunctionCall submit_blocks, block 276471445). NEAR nodes prune old
// transactions, so if this hash ever goes stale, replace it with a fresh
// hash from a recent block (e.g. via the `block` + `chunk` RPC calls).
const REAL_TX_HASH = 'F5rjbPaDnsyQ6EnWQaY7ZT8PpHwHvQ3ZDDdNb1vonxdF';
const REAL_TX_SENDER = 'btc-relayer.testnet';
// Same hash with the last char changed: well-formed base58, but no such
// transaction exists. Used as the "genuinely missing" tx.
const MISSING_TX_HASH = 'F5rjbPaDnsyQ6EnWQaY7ZT8PpHwHvQ3ZDDdNb1vonxd1';

test('computeDataHash: same input -> same hash; any change -> different hash', () => {
  const txs = [{
    hash: 'A'.repeat(43), senderId: 'alice.testnet', receiverId: 'bob.testnet',
    amountYocto: '1000000000000000000000000', status: 'Success',
    blockHeight: 100, blockTimestampNs: '1793958583519543793',
  }];
  const h1 = computeDataHash('alice.testnet', '10000000000000000000000000', '0', txs);
  assert.match(h1, /^[0-9a-f]{64}$/);
  assert.equal(computeDataHash('alice.testnet', '10000000000000000000000000', '0', txs), h1);
  // Tx order must not matter (txs are sorted before hashing).
  assert.equal(computeDataHash('alice.testnet', '10000000000000000000000000', '0', [...txs].reverse()), h1);
  // One yocto changes the hash.
  assert.notEqual(computeDataHash('alice.testnet', '10000000000000000000000001', '0', txs), h1);
  // One tx field changes the hash.
  assert.notEqual(computeDataHash('alice.testnet', '10000000000000000000000000', '0',
    [{ ...txs[0], amountYocto: '1000000000000000000000001' }]), h1);
  // Locked balance is part of the payload too.
  assert.notEqual(computeDataHash('alice.testnet', '10000000000000000000000000', '1', txs), h1);
});

test('getAccount: veilproof-demo.testnet holds funding + recorded demo transfers (minus gas)', async () => {
  const account = await getAccount('veilproof-demo.testnet');
  assert.equal(account.accountId, 'veilproof-demo.testnet');
  assertDemoBalance(account.amount);
  assert.equal(account.locked, '0');
  assert.equal(typeof account.storage_usage, 'number');
  assert.ok(account.blockHeight > 0);
});

test('getAccount: nonexistent account throws', async () => {
  await assert.rejects(() => getAccount('does-not-exist-xyz123.testnet'));
});

test('verifyTx: real tx returns the verified shape', async () => {
  const verified = await verifyTx(REAL_TX_HASH, REAL_TX_SENDER);
  assert.equal(verified.hash, REAL_TX_HASH);
  assert.equal(verified.senderId, 'btc-relayer.testnet');
  assert.equal(verified.receiverId, 'btc-client-v4.testnet');
  assert.equal(verified.status, 'Success');
  // FunctionCall, not a Transfer: amount is "0" by rule.
  assert.equal(verified.amountYocto, '0');
  assert.equal(verified.blockHeight, 276471445);
  assert.match(verified.blockTimestampNs, /^\d+$/);
  assert.ok(BigInt(verified.blockTimestampNs) > 0n);
});

test('verifyTx: made-up hash returns null (slow: node timeouts)', async () => {
  const verified = await verifyTx(MISSING_TX_HASH, REAL_TX_SENDER);
  assert.equal(verified, null);
});

test('verifyTx: malformed hash throws instead of returning null', async () => {
  await assert.rejects(() => verifyTx('not-a-base58-hash!!', REAL_TX_SENDER), /base58/);
  await assert.rejects(() => verifyTx('', REAL_TX_SENDER), /base58/);
});

test('fetchAccountSnapshot: demo wallet, no txs', async () => {
  const snap = await fetchAccountSnapshot('veilproof-demo.testnet', []);
  assertDemoBalance(snap.account.amount);
  assert.deepEqual(snap.txs, []);
  assert.ok(snap.blockHeight > 0);
  assert.match(snap.dataHash, /^[0-9a-f]{64}$/);
  assert.equal(snap.dataHash, computeDataHash('veilproof-demo.testnet', snap.account.amount, snap.account.locked, []));
});

test('fetchAccountSnapshot: { hash, senderId } entry verifies an incoming-style tx', async () => {
  const snap = await fetchAccountSnapshot('veilproof-demo.testnet', [
    { hash: REAL_TX_HASH, senderId: REAL_TX_SENDER },
  ]);
  assert.equal(snap.txs.length, 1);
  assert.equal(snap.txs[0].hash, REAL_TX_HASH);
  assert.equal(snap.txs[0].status, 'Success');
});

test('fetchAccountSnapshot: unknown hashes are skipped, duplicates collapsed', async () => {
  const snap = await fetchAccountSnapshot('veilproof-demo.testnet', [
    MISSING_TX_HASH,
    { hash: REAL_TX_HASH, senderId: REAL_TX_SENDER },
    { hash: REAL_TX_HASH, senderId: REAL_TX_SENDER },
  ]);
  assert.equal(snap.txs.length, 1);
  assert.equal(snap.txs[0].hash, REAL_TX_HASH);
});

test('computeSampleHeights: deterministic spacing, newest last', () => {
  assert.deepEqual(computeSampleHeights(100000, { windowHours: 1, samples: 4 }), [97300, 98200, 99100, 100000]);
  assert.deepEqual(computeSampleHeights(100000, { windowHours: 0.5, samples: 4 }), [98650, 99100, 99550, 100000]);
  assert.throws(() => computeSampleHeights(100, { windowHours: 24, samples: 4 }), /negative/);
  assert.throws(() => computeSampleHeights(100000, { windowHours: 0, samples: 4 }), /windowHours/);
  assert.throws(() => computeSampleHeights(100000, { windowHours: 1, samples: 1 }), /samples/);
});

// The linked demo wallet (demo2.veilproof.testnet) is young: a 15-minute
// window's oldest sample is ~11 minutes back, safely after its creation.
// Explicit heights are the point of this test — two wallets sampled at
// the same heights must come back with identical blockHeight arrays,
// or the sustained/time-weighted claims refuse to run.
test('sampleBalanceHistory: explicit heights align across two wallets', async () => {
  const primary = await getAccount(DEMO_ACCOUNT);
  const heights = computeSampleHeights(primary.blockHeight, { windowHours: 0.25, samples: 4 });
  const a = await sampleBalanceHistory(DEMO_ACCOUNT, { windowHours: 0.25, samples: 4, heights });
  const b = await sampleBalanceHistory('demo2.veilproof.testnet', { windowHours: 0.25, samples: 4, heights });
  assert.deepEqual(a.map((s) => s.blockHeight), heights);
  assert.deepEqual(b.map((s) => s.blockHeight), heights);
  assert.ok(BigInt(b[3].amount) > 0n, 'linked wallet balance should be positive');
});
