// Verifier-bound disclosure (P4) — browser mirror of src/crypto-box.js.
//
// Same shapes and validation, but Web Crypto (async) for SHA-256 and
// the vendored tweetnacl global (public/js/nacl.min.js, loaded by a
// <script> tag before this module) for the box. So the fingerprint and
// encrypt functions are async here (sync in Node); open is sync on
// both paths, because opening needs no hash — decryption itself proves
// the package was encrypted to this verifier's key.
//
// The browser cannot import ../src/ (Vercel serves only public/), so
// the prover page carries this copy. The parity test asserts the two
// paths agree: same ciphertext given the same keys + nonce, and
// cross-path round-trips (Node encrypts, browser opens, and back).
import { sha256Hex } from './crypto.js';
import { canonicalJson } from './canonical.js';

export const ENCRYPTED_DISCLOSURE_VERSION = 'veilproof-encrypted-disclosure-v1';

function requireNacl() {
  const nacl = globalThis.nacl;
  if (!nacl || !nacl.box || typeof nacl.box.before !== 'function') {
    throw new Error('crypto-box: tweetnacl (nacl.min.js) is not loaded');
  }
  return nacl;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function bytesToBase64(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

function base64ToBytes(str, what) {
  if (typeof str !== 'string' || str.length === 0) {
    throw new Error(`crypto-box: ${what} must be a non-empty base64 string`);
  }
  const s = atob(str);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

function requireKey(bytes, what) {
  const nacl = requireNacl();
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
  const nacl = requireNacl();
  const pair = nacl.box.keyPair();
  return { publicKey: bytesToBase64(pair.publicKey), secretKey: bytesToBase64(pair.secretKey) };
}

// Fingerprint of a verifier's public key (base64): SHA-256 of the
// hex-encoded key, matching src/crypto-box.js exactly.
export async function verifierKeyFingerprint(publicKeyBase64) {
  const bytes = requireKey(base64ToBytes(publicKeyBase64, 'verifier public key'), 'verifier public key');
  return sha256Hex(bytesToHex(bytes));
}

// Encrypt a disclosure package for one verifier. expiresAt is the
// nanosecond epoch (decimal string) after which the package must not
// be opened — pass the report's expiresAt so the package dies with it.
export async function encryptDisclosurePackage(disclosurePackage, verifierPublicKeyBase64, expiresAt) {
  const nacl = requireNacl();
  if (!disclosurePackage || typeof disclosurePackage !== 'object' || Array.isArray(disclosurePackage)) {
    throw new Error('crypto-box: disclosurePackage must be an object');
  }
  const verifierPublicKey = requireKey(base64ToBytes(verifierPublicKeyBase64, 'verifier public key'), 'verifier public key');
  const expires = requireNsEpoch(expiresAt, 'expiresAt');
  const ephemeral = nacl.box.keyPair();
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  const shared = nacl.box.before(verifierPublicKey, ephemeral.secretKey);
  const plaintext = new TextEncoder().encode(canonicalJson(disclosurePackage));
  const ciphertext = nacl.box.after(plaintext, nonce, shared);
  return {
    version: ENCRYPTED_DISCLOSURE_VERSION,
    verifierKeyFingerprint: await sha256Hex(bytesToHex(verifierPublicKey)),
    ephemeralPublicKey: bytesToBase64(ephemeral.publicKey),
    nonce: bytesToBase64(nonce),
    ciphertext: bytesToBase64(ciphertext),
    expiresAt: expires.toString(),
  };
}

// Open an encrypted disclosure package. Throws when the package is
// expired, malformed, tampered with, or opened with the wrong key.
// nowNs is the current time as a nanosecond epoch (decimal string).
export function openDisclosurePackage(encryptedPackage, verifierSecretKeyBase64, nowNs) {
  const nacl = requireNacl();
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
  const verifierSecretKey = requireKey(base64ToBytes(verifierSecretKeyBase64, 'verifier secret key'), 'verifier secret key');
  const ephemeralPublicKey = requireKey(
    base64ToBytes(encryptedPackage.ephemeralPublicKey, 'ephemeral public key'),
    'ephemeral public key',
  );
  const nonce = base64ToBytes(encryptedPackage.nonce, 'nonce');
  if (nonce.length !== nacl.box.nonceLength) {
    throw new Error(`crypto-box: nonce must be ${nacl.box.nonceLength} bytes`);
  }
  const ciphertext = base64ToBytes(encryptedPackage.ciphertext, 'ciphertext');
  const shared = nacl.box.before(ephemeralPublicKey, verifierSecretKey);
  const plaintext = nacl.box.open.after(ciphertext, nonce, shared);
  if (plaintext === null) {
    throw new Error('crypto-box: could not decrypt, wrong verifier key or tampered package');
  }
  let parsed;
  try {
    parsed = JSON.parse(new TextDecoder().decode(plaintext));
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
