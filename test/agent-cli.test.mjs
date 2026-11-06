// Agent CLI tests (scripts/agent-prove.mjs).
//
// The arg-parsing cases are pure and fast. The dry-run case is LIVE
// against NEAR testnet RPC (it fetches the demo wallets' snapshots),
// like test/onchain.test.mjs — slower, but it is the only way to
// prove the CLI works end to end. It never publishes (no --publish),
// never calls the underwriting route (--no-underwrite), and writes
// its output to a temp dir.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const CLI = new URL('../scripts/agent-prove.mjs', import.meta.url).pathname;
const KEYS = new URL('../.testnet-agent-keys.json', import.meta.url).pathname;
const POLICY = new URL('../examples/agent-policy.json', import.meta.url).pathname;
const TXS = new URL('../demo/history.json', import.meta.url).pathname;

function run(args) {
  return spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', timeout: 240000 });
}

test('agent CLI: --help prints usage and exits 0', () => {
  const r = run(['--help']);
  assert.equal(r.status, 0);
  assert.match(r.stdout, /--keys <file>/);
  assert.match(r.stdout, /--publish/);
});

test('agent CLI: unknown argument, missing --keys and missing --policy fail with exit 1', () => {
  const unknown = run(['--nope']);
  assert.equal(unknown.status, 1);
  assert.match(unknown.stderr, /unknown argument/);
  const noKeys = run(['--policy', POLICY]);
  assert.equal(noKeys.status, 1);
  assert.match(noKeys.stderr, /--keys is required/);
  const noPolicy = run(['--keys', KEYS]);
  assert.equal(noPolicy.status, 1);
  assert.match(noPolicy.stderr, /--policy is required/);
});

test('agent CLI: dry run against the demo wallets builds a signature-linked report and verifies all 10 checks', { timeout: 240000 }, () => {
  const out = mkdtempSync(join(tmpdir(), 'agent-prove-'));
  const r = run([
    '--keys', KEYS,
    '--policy', POLICY,
    '--txs', TXS,
    '--sample-window', '1',
    '--no-underwrite',
    '--out', out,
  ]);
  assert.equal(r.status, 0, `CLI failed: ${r.stderr}\n${r.stdout}`);
  assert.match(r.stdout, /score 770 \(solid\)/);
  assert.match(r.stdout, /check link_proofs: PASS — All 1 linked wallet\(s\) proved ownership \(1 by signature\)/);
  assert.match(r.stdout, /PASS — all 10 checks pass locally/);
  assert.match(r.stdout, /"published": false/);
  const report = JSON.parse(readFileSync(join(out, 'report.json'), 'utf8'));
  const disclosure = JSON.parse(readFileSync(join(out, 'disclosure.json'), 'utf8'));
  const policy = JSON.parse(readFileSync(join(out, 'policy.json'), 'utf8'));
  assert.match(report.reportId, /^[0-9a-f]{16}$/);
  // P3: the public report carries the band, not the exact score or
  // exact claim values — the CLI still prints the prover's own exact
  // score (770) to its own terminal, which the stdout assertion above
  // covers.
  assert.equal(report.score.value, undefined);
  assert.equal(report.score.band, 'solid');
  assert.ok(report.claims.every((c) => c.value === undefined));
  assert.ok(report.claims.every((c) => typeof c.threshold === 'string' || typeof c.threshold === 'number'));
  assert.equal(report.aiSummary, null);
  assert.equal(disclosure.linked.length, 1);
  assert.equal(disclosure.linked[0].address, 'demo2.veilproof.testnet');
  assert.equal(typeof disclosure.linked[0].linkSignature, 'object');
  assert.equal(disclosure.linked[0].linkSignature.message, 'VeilProof link\nLinked wallet: demo2.veilproof.testnet\nPrimary wallet: veilproof-demo.testnet');
  assert.equal(disclosure.linked[0].linkTxHash, undefined);
  assert.equal(policy.aggregateBalanceAtLeastYocto, '10000000000000000000000000');
  assert.ok(existsSync(join(out, 'report.json')));
});

test('agent CLI: --verifier-key writes an encrypted disclosure only the verifier can open', { timeout: 240000 }, async () => {
  const { newVerifierKeypair, openDisclosurePackage, isEncryptedDisclosurePackage } = await import('../src/crypto-box.js');
  const keys = newVerifierKeypair();
  const out = mkdtempSync(join(tmpdir(), 'agent-prove-enc-'));
  const r = run([
    '--keys', KEYS,
    '--policy', POLICY,
    '--txs', TXS,
    '--sample-window', '1',
    '--no-underwrite',
    '--verifier-key', keys.publicKey,
    '--out', out,
  ]);
  assert.equal(r.status, 0, `CLI failed: ${r.stderr}\n${r.stdout}`);
  assert.match(r.stdout, /disclosure-encrypted\.json/);
  const encrypted = JSON.parse(readFileSync(join(out, 'disclosure-encrypted.json'), 'utf8'));
  const plain = JSON.parse(readFileSync(join(out, 'disclosure.json'), 'utf8'));
  const report = JSON.parse(readFileSync(join(out, 'report.json'), 'utf8'));
  assert.equal(isEncryptedDisclosurePackage(encrypted), true);
  assert.equal(encrypted.expiresAt, report.expiresAt);
  // Only the verifier's key opens it, back to exactly the plaintext package.
  const opened = openDisclosurePackage(encrypted, keys.secretKey, String(BigInt(Date.now()) * 1000000n));
  assert.deepEqual(opened, plain);
  // A different verifier key cannot open it.
  const other = newVerifierKeypair();
  assert.throws(() => openDisclosurePackage(encrypted, other.secretKey, String(BigInt(Date.now()) * 1000000n)), /could not decrypt/);
});
