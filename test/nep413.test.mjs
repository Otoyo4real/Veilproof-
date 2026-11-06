// NEP-413 link signatures (src/nep413.js + browser mirror).
//
// The payload bytes are pinned to a hand-computed vector so a
// drift in the Borsh encoding (tag, lengths, nonce, recipient,
// callback) fails loudly here instead of silently producing
// signatures no wallet would ever make.
import test from 'node:test';
import assert from 'node:assert/strict';
import nacl from 'tweetnacl';
import {
  NEP413_TAG,
  LINK_RECIPIENT,
  base58Decode,
  base58Encode,
  buildLinkMessage,
  nep413PayloadBytes,
  signLinkMessage,
  verifyLinkSignature,
} from '../src/nep413.js';

const NONCE_ZERO_B64 = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';

test('nep413: payload bytes match the hand-computed vector', () => {
  const msg = buildLinkMessage('a.testnet', 'b.testnet');
  assert.equal(msg, 'VeilProof link\nLinked wallet: a.testnet\nPrimary wallet: b.testnet');
  const payload = nep413PayloadBytes(msg, NONCE_ZERO_B64, 'registry.veilproof.testnet');
  // tag (4) + message string (4 + 65) + nonce (32) + recipient (4 + 26) + callback (1) = 136.
  assert.equal(payload.length, 136);
  assert.deepEqual([...payload.slice(0, 4)], [0x9d, 0x01, 0x00, 0x80]); // u32 LE of 2147484061
  assert.equal(NEP413_TAG, 2147484061);
  assert.deepEqual([...payload.slice(4, 8)], [65, 0, 0, 0]); // message byte length
  assert.equal(payload.slice(73, 105).every((b) => b === 0), true); // zero nonce
  assert.equal(Buffer.from(payload.slice(109, 135)).toString(), 'registry.veilproof.testnet');
  assert.deepEqual([...payload.slice(105, 109)], [26, 0, 0, 0]); // recipient byte length
  assert.equal(payload[135], 0); // callbackUrl: None
  assert.equal(LINK_RECIPIENT, 'registry.veilproof.testnet');
});

test('nep413: base58 round-trips, including leading zero bytes', () => {
  const bytes = new Uint8Array([0, 0, 1, 2, 255, 0, 128]);
  assert.deepEqual(base58Decode(base58Encode(bytes)), bytes);
  assert.equal(base58Encode(new Uint8Array(32)), '1'.repeat(32));
  assert.throws(() => base58Decode('0OIl'), /invalid base58/);
  assert.throws(() => base58Decode(''), /non-empty/);
});

test('nep413: sign + verify round-trips; tampering fails', () => {
  const kp = nacl.sign.keyPair();
  const sig = signLinkMessage(kp.secretKey, 'a.testnet', 'b.testnet', NONCE_ZERO_B64);
  assert.equal(sig.recipient, LINK_RECIPIENT);
  assert.equal(sig.message, buildLinkMessage('a.testnet', 'b.testnet'));
  assert.equal(verifyLinkSignature(sig), true);
  // Tampered message, recipient, signature, public key, nonce: all fail.
  assert.equal(verifyLinkSignature({ ...sig, message: sig.message + '!' }), false);
  assert.equal(verifyLinkSignature({ ...sig, recipient: 'evil.testnet' }), false);
  const other = nacl.sign.keyPair();
  const sigOther = signLinkMessage(other.secretKey, 'a.testnet', 'b.testnet', NONCE_ZERO_B64);
  assert.equal(verifyLinkSignature({ ...sig, signature: sigOther.signature }), false);
  assert.equal(verifyLinkSignature({ ...sig, publicKey: sigOther.publicKey }), false);
  assert.equal(verifyLinkSignature({ ...sig, nonce: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' }), true); // same zero nonce
  assert.equal(verifyLinkSignature({ ...sig, nonce: 'AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' }), false);
  assert.equal(verifyLinkSignature({ ...sig, signature: '!!!not-base64!!!' }), false);
  assert.equal(verifyLinkSignature({ ...sig, signature: Buffer.from(new Uint8Array(10)).toString('base64') }), false);
  assert.throws(() => verifyLinkSignature(null), /must be an object/);
  assert.throws(() => verifyLinkSignature(undefined), /must be an object/);
  assert.throws(() => signLinkMessage(new Uint8Array(32), 'a.testnet', 'b.testnet', NONCE_ZERO_B64), /64-byte/);
  assert.throws(() => nep413PayloadBytes('m', 'AAAA', 'r'), /32 bytes/);
});

test('nep413: browser mirror agrees with the Node module', async () => {
  globalThis.nacl = nacl;
  const browser = await import('../public/js/nep413.js');
  const kp = nacl.sign.keyPair();
  const sig = signLinkMessage(kp.secretKey, 'a.testnet', 'b.testnet', NONCE_ZERO_B64);
  // Same payload bytes, same verdicts, both directions.
  const msg = buildLinkMessage('a.testnet', 'b.testnet');
  assert.deepEqual(browser.nep413PayloadBytes(msg, NONCE_ZERO_B64, 'registry.veilproof.testnet'), nep413PayloadBytes(msg, NONCE_ZERO_B64, 'registry.veilproof.testnet'));
  assert.equal(await browser.verifyLinkSignature(sig), true);
  assert.equal(await browser.verifyLinkSignature({ ...sig, message: msg + '!' }), false);
  assert.equal(browser.buildLinkMessage('a.testnet', 'b.testnet'), msg);
  assert.deepEqual(browser.base58Decode(browser.base58Encode(new Uint8Array([1, 2, 3]))), new Uint8Array([1, 2, 3]));
});
