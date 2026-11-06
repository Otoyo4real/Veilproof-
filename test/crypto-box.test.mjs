// Verifier-bound disclosure tests (P4) — pure, no network.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { evaluateClaims } from '../src/claims-engine.js';
import { computeDataHash } from '../src/onchain.js';
import { buildReport, newProverSalt, saltedAddressHash } from '../src/report.js';
import { buildDisclosurePackage } from '../src/disclosure.js';
import {
  ENCRYPTED_DISCLOSURE_VERSION,
  newVerifierKeypair,
  verifierKeyFingerprint,
  encryptDisclosurePackage,
  openDisclosurePackage,
  isEncryptedDisclosurePackage,
} from '../src/crypto-box.js';

const ADDRESS = 'alice.veilproof.testnet';
const NOW_NS = 1793961600000000000n;
const DAY_NS = 86400n * 1_000_000_000n;
const EXPIRES_AT = (NOW_NS + 30n * DAY_NS).toString();
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

function snapshot() {
  const snap = {
    account: {
      accountId: ADDRESS,
      amount: '5000000000000000000000000',
      locked: '2000000000000000000000000',
      storage_usage: 1000,
      blockHeight: 100,
    },
    txs: [
      {
        hash: 'A'.repeat(43),
        senderId: ADDRESS,
        receiverId: 'bob.veilproof.testnet',
        amountYocto: '1000000000000000000000000',
        status: 'Success',
        blockHeight: 100,
        blockTimestampNs: (NOW_NS - 10n * DAY_NS).toString(),
      },
    ],
    blockHeight: 100,
  };
  snap.dataHash = computeDataHash(snap.account.accountId, snap.account.amount, snap.account.locked, snap.txs);
  return snap;
}

function realDisclosurePackage() {
  const salt = newProverSalt();
  const snap = snapshot();
  const { claims } = evaluateClaims(snap, POLICY, NOW_NS);
  const report = buildReport({
    proverAddressHash: saltedAddressHash(salt, ADDRESS),
    claims,
    policyVersion: POLICY_VERSION,
    aiSummary: null,
    evidenceRefs: { dataHash: snap.dataHash, attestationRef: null },
    expiresAt: EXPIRES_AT,
  });
  return { disclosure: buildDisclosurePackage(report, ADDRESS, snap, salt), report };
}

test('verifier keypair: fresh 32-byte Curve25519 keys, base64, distinct each time', () => {
  const a = newVerifierKeypair();
  const b = newVerifierKeypair();
  assert.notEqual(a.publicKey, b.publicKey);
  assert.notEqual(a.secretKey, b.secretKey);
  for (const k of [a.publicKey, a.secretKey, b.publicKey, b.secretKey]) {
    assert.equal(Buffer.from(k, 'base64').length, 32);
  }
  assert.equal(verifierKeyFingerprint(a.publicKey), sha256Hex(Buffer.from(a.publicKey, 'base64').toString('hex')));
  assert.match(verifierKeyFingerprint(a.publicKey), /^[0-9a-f]{64}$/);
  assert.notEqual(verifierKeyFingerprint(a.publicKey), verifierKeyFingerprint(b.publicKey));
});

test('encrypt/open round-trip: a real disclosure package survives and nothing leaks in the ciphertext', () => {
  const { disclosure, report } = realDisclosurePackage();
  const keys = newVerifierKeypair();
  const encrypted = encryptDisclosurePackage(disclosure, keys.publicKey, report.expiresAt);
  assert.equal(encrypted.version, ENCRYPTED_DISCLOSURE_VERSION);
  assert.equal(encrypted.verifierKeyFingerprint, verifierKeyFingerprint(keys.publicKey));
  assert.equal(encrypted.expiresAt, report.expiresAt);
  assert.equal(isEncryptedDisclosurePackage(encrypted), true);
  assert.equal(isEncryptedDisclosurePackage(disclosure), false);
  // No plaintext anywhere in the encrypted package: not the address,
  // not a salt, not a tx hash, not a balance.
  const json = JSON.stringify(encrypted);
  assert.equal(json.includes(ADDRESS), false);
  assert.equal(json.includes(disclosure.salt), false);
  assert.equal(json.includes(disclosure.snapshot.txs[0].hash), false);
  assert.equal(json.includes('5000000000000000000000000'), false);
  // Two encryptions of the same package differ (fresh ephemeral key +
  // nonce), so ciphertexts cannot be matched either.
  const again = encryptDisclosurePackage(disclosure, keys.publicKey, report.expiresAt);
  assert.notEqual(again.ciphertext, encrypted.ciphertext);
  assert.notEqual(again.ephemeralPublicKey, encrypted.ephemeralPublicKey);
  // And the verifier opens it back to exactly the original package.
  const opened = openDisclosurePackage(encrypted, keys.secretKey, NOW_NS.toString());
  assert.deepEqual(opened, disclosure);
});

test('open rejects a wrong verifier key, tampered ciphertext, nonce and ephemeral key', () => {
  const { disclosure, report } = realDisclosurePackage();
  const keys = newVerifierKeypair();
  const other = newVerifierKeypair();
  const encrypted = encryptDisclosurePackage(disclosure, keys.publicKey, report.expiresAt);
  assert.throws(() => openDisclosurePackage(encrypted, other.secretKey, NOW_NS.toString()), /could not decrypt/);
  const tamperedCipher = { ...encrypted, ciphertext: Buffer.from('A'.repeat(64), 'utf8').toString('base64') };
  assert.throws(() => openDisclosurePackage(tamperedCipher, keys.secretKey, NOW_NS.toString()), /could not decrypt/);
  const tamperedNonce = { ...encrypted, nonce: Buffer.from(new Uint8Array(24).fill(7)).toString('base64') };
  assert.throws(() => openDisclosurePackage(tamperedNonce, keys.secretKey, NOW_NS.toString()), /could not decrypt/);
  const tamperedEphemeral = { ...encrypted, ephemeralPublicKey: other.publicKey };
  assert.throws(() => openDisclosurePackage(tamperedEphemeral, keys.secretKey, NOW_NS.toString()), /could not decrypt/);
});

test('open rejects an expired package and a bad version', () => {
  const { disclosure, report } = realDisclosurePackage();
  const keys = newVerifierKeypair();
  const expired = encryptDisclosurePackage(disclosure, keys.publicKey, (NOW_NS - 1n).toString());
  assert.throws(() => openDisclosurePackage(expired, keys.secretKey, NOW_NS.toString()), /expired/);
  // Expiring exactly at now is expired too.
  const atNow = encryptDisclosurePackage(disclosure, keys.publicKey, NOW_NS.toString());
  assert.throws(() => openDisclosurePackage(atNow, keys.secretKey, NOW_NS.toString()), /expired/);
  const future = encryptDisclosurePackage(disclosure, keys.publicKey, report.expiresAt);
  assert.doesNotThrow(() => openDisclosurePackage(future, keys.secretKey, NOW_NS.toString()));
  const badVersion = { ...future, version: 'veilproof-encrypted-disclosure-v99' };
  assert.throws(() => openDisclosurePackage(badVersion, keys.secretKey, NOW_NS.toString()), /unsupported.*version/);
  assert.throws(() => openDisclosurePackage(future, keys.secretKey, 'not-a-number'), /nanosecond epoch/);
});

test('encrypt rejects bad inputs', () => {
  const keys = newVerifierKeypair();
  assert.throws(() => encryptDisclosurePackage(null, keys.publicKey, EXPIRES_AT), /must be an object/);
  assert.throws(() => encryptDisclosurePackage({ address: ADDRESS }, 'not-base64!!!', EXPIRES_AT), /32-byte/);
  assert.throws(() => encryptDisclosurePackage({ address: ADDRESS }, keys.publicKey, 'yesterday'), /nanosecond epoch/);
  assert.throws(() => encryptDisclosurePackage({ address: ADDRESS }, keys.publicKey, (-1n).toString()), /nanosecond epoch/);
});
