// Verifier-bound disclosure (P4).
//
// The disclosure package is encrypted to ONE verifier's public key, so
// only that verifier can open it. A verifier who forwards the package
// forwards ciphertext, not the data — the exact balances, transactions
// and salts stay sealed to anyone else.
//
// The verifier's key is a SEPARATE encryption keypair (Curve25519),
// NOT their NEAR ed25519 signing key. Two reasons: ed25519 keys cannot
// be used directly for nacl.box (the box needs a Curve25519 key), and
// reusing a signing key for encryption is poor practice. The verifier
// generates a keypair with newVerifierKeypair() and publishes the
// public key (base64); the prover encrypts to it. How the prover
// learns the key is out of scope here — in practice the verifier hands
// it over with their request (and can sign it with their NEAR key if
// the prover wants proof it is theirs).
//
// Scheme: ephemeral-key nacl.box — the sealed-box construction. The
// prover generates a fresh ephemeral keypair per package, derives the
// shared secret from the verifier's public key + the ephemeral secret,
// and encrypts the canonical JSON of the disclosure package under a
// fresh random nonce. The package ships the ephemeral public key, the
// nonce and the ciphertext. The verifier derives the same shared secret
// from the ephemeral public key + their secret key. nacl.box is
// authenticated encryption (Poly1305), so any tampering with the
// ciphertext, nonce or ephemeral key fails the open.
//
// Expiry: the package carries expiresAt (nanosecond epoch, same units
// as the report's expiresAt). openDisclosurePackage rejects an expired
// package BEFORE decrypting. Callers pass the report's expiresAt so
// the package dies when the report does. The report's own expiry is
// still checked by verifyReport — the package expiry is an additional,
// earlier gate.
//
// The verifier never needs the prover's key: the ephemeral key is
// inside the package. The prover never learns the verifier's secret
// key. Neither side needs a shared secret set up in advance.
//
// Keys are base64 (the NEAR convention). The fingerprint is the
// SHA-256 of the verifier's public key, so the verifier can confirm
// a package is addressed to them before trying to open it.
import { createHash } from 'node:crypto';
import nacl from 'tweetnacl';
import { canonicalJson } from './canonical.js';

export const ENCRYPTED_DISCLOSURE_VERSION = 'veilproof-encrypted-disclosure-v1';

function sha256Hex(s) {
  return createHash('sha256').update(s, 'utf8').digest('hex');
}

function toBase64(bytes) {
  return Buffer.from(bytes).toString('base64');
}

function fromBase64(str, what) {
  if (typeof str !== 'string' || str.length === 0) {
    throw new Error(`crypto-box: ${what} must be a non-empty base64 string`);
  }
  // Buffer.from is lenient about stray characters, so a bad string
  // decodes to the wrong bytes — the length checks in requireKey and
  // the box authentication tag catch that downstream. This only
  // rejects non-strings and empty input here.
  return Buffer.from(str, 'base64');
}

function requireKey(bytes, what) {
  if (!(bytes instanceof Uint8Array) || bytes.length !== nacl.box.publicKeyLength) {
    throw new Error(`crypto-box: ${what} must be a ${nacl.box.publicKeyLength}-byte Curve25519 key`);
  }
  return bytes;
}

function requireNsEpoch(value, what) {
  if (typeof value !== 'string' && typeof value !== 'bigint') {
    throw new Error(`crypto-box: ${what} must be a nanosecond epoch as a decimal string`);
  }
  try {
    const n = BigInt(value);
    if (n < 0n) throw new Error('negative');
    return n;
  } catch {
    throw new Error(`crypto-box: ${what} must be a nanosecond epoch as a decimal string`);
  }
}

// Generate a fresh verifier encryption keypair. The public key is what
// the prover encrypts to; the secret key never leaves the verifier.
export function newVerifierKeypair() {
  const pair = nacl.box.keyPair();
  return { publicKey: toBase64(pair.publicKey), secretKey: toBase64(pair.secretKey) };
}

// Fingerprint of a verifier's public key (base64): SHA-256 hex, so the
// verifier can confirm a package is addressed to them.
export function verifierKeyFingerprint(publicKeyBase64) {
  const bytes = requireKey(fromBase64(publicKeyBase64, 'verifier public key'), 'verifier public key');
  return sha256Hex(Buffer.from(bytes).toString('hex'));
}

// Encrypt a disclosure package for one verifier. expiresAt is the
// nanosecond epoch (decimal string) after which the package must not
// be opened — pass the report's expiresAt so the package dies with it.
export function encryptDisclosurePackage(disclosurePackage, verifierPublicKeyBase64, expiresAt) {
  if (!disclosurePackage || typeof disclosurePackage !== 'object' || Array.isArray(disclosurePackage)) {
    throw new Error('crypto-box: disclosurePackage must be an object');
  }
  const verifierPublicKey = requireKey(fromBase64(verifierPublicKeyBase64, 'verifier public key'), 'verifier public key');
  const expires = requireNsEpoch(expiresAt, 'expiresAt');
  const ephemeral = nacl.box.keyPair();
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  const shared = nacl.box.before(verifierPublicKey, ephemeral.secretKey);
  const plaintext = Buffer.from(canonicalJson(disclosurePackage), 'utf8');
  const ciphertext = nacl.box.after(plaintext, nonce, shared);
  return {
    version: ENCRYPTED_DISCLOSURE_VERSION,
    verifierKeyFingerprint: sha256Hex(Buffer.from(verifierPublicKey).toString('hex')),
    ephemeralPublicKey: toBase64(ephemeral.publicKey),
    nonce: toBase64(nonce),
    ciphertext: toBase64(ciphertext),
    expiresAt: expires.toString(),
  };
}

// Open an encrypted disclosure package. Throws when the package is
// expired, malformed, tampered with, or opened with the wrong key.
// nowNs is the current time as a nanosecond epoch (decimal string).
export function openDisclosurePackage(encryptedPackage, verifierSecretKeyBase64, nowNs) {
  if (!encryptedPackage || typeof encryptedPackage !== 'object' || Array.isArray(encryptedPackage)) {
    throw new Error('crypto-box: encrypted package must be an object');
  }
  if (encryptedPackage.version !== ENCRYPTED_DISCLOSURE_VERSION) {
    throw new Error(`crypto-box: unsupported encrypted package version ${JSON.stringify(encryptedPackage.version)}`);
  }
  const now = requireNsEpoch(nowNs, 'nowNs');
  const expires = requireNsEpoch(encryptedPackage.expiresAt, 'expiresAt');
  if (expires <= now) {
    throw new Error('crypto-box: disclosure package expired');
  }
  const verifierSecretKey = requireKey(fromBase64(verifierSecretKeyBase64, 'verifier secret key'), 'verifier secret key');
  const ephemeralPublicKey = requireKey(
    fromBase64(encryptedPackage.ephemeralPublicKey, 'ephemeral public key'),
    'ephemeral public key',
  );
  const nonce = fromBase64(encryptedPackage.nonce, 'nonce');
  if (nonce.length !== nacl.box.nonceLength) {
    throw new Error(`crypto-box: nonce must be ${nacl.box.nonceLength} bytes`);
  }
  const ciphertext = fromBase64(encryptedPackage.ciphertext, 'ciphertext');
  const shared = nacl.box.before(ephemeralPublicKey, verifierSecretKey);
  const plaintext = nacl.box.open.after(ciphertext, nonce, shared);
  if (plaintext === null) {
    throw new Error('crypto-box: could not decrypt, wrong verifier key or tampered package');
  }
  let parsed;
  try {
    parsed = JSON.parse(Buffer.from(plaintext).toString('utf8'));
  } catch {
    throw new Error('crypto-box: decrypted package is not valid JSON');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('crypto-box: decrypted package is not a disclosure package');
  }
  return parsed;
}

// True when the value looks like an encrypted disclosure package
// (shape only — it does not try to open it).
export function isEncryptedDisclosurePackage(value) {
  return (
    !!value &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    value.version === ENCRYPTED_DISCLOSURE_VERSION &&
    typeof value.ephemeralPublicKey === 'string' &&
    typeof value.nonce === 'string' &&
    typeof value.ciphertext === 'string' &&
    typeof value.expiresAt === 'string'
  );
}
