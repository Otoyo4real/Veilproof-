// NEP-413 signed messages, for the signature link proof.
//
// A linked wallet can prove ownership WITHOUT an onchain transfer: it
// signs a short link statement ("VeilProof link: <linked> -> <primary>")
// with its key, and the verifier checks the signature against the
// linked account's public key (fetched from the chain's access key
// list). No gas, no transfer, and — unlike the transfer link — no
// public onchain record connecting the two wallets.
//
// The signature is a NEP-413 signature: ed25519 over SHA-256 of the
// Borsh-serialised payload { tag: u32 2147484061, message: String,
// nonce: [u8; 32], recipient: String, callbackUrl: Option<String> }.
// The wallet's signMessage produces exactly this; this module
// reconstructs the payload so the signature can be checked by anyone
// with the message, nonce, recipient, signature and public key.
//
// ed25519 verification uses tweetnacl (same library in Node and in the
// browser, so the two paths agree exactly). SHA-256 uses node:crypto
// here; the browser mirror uses Web Crypto (async).
import { createHash } from 'node:crypto';
import nacl from 'tweetnacl';

export const NEP413_TAG = 2147484061;
export const LINK_RECIPIENT = 'registry.veilproof.testnet';

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function base58Decode(str) {
  if (typeof str !== 'string' || str.length === 0) throw new Error('nep413: base58 input must be a non-empty string');
  let num = 0n;
  for (const ch of str) {
    const idx = BASE58_ALPHABET.indexOf(ch);
    if (idx === -1) throw new Error('nep413: invalid base58 character');
    num = num * 58n + BigInt(idx);
  }
  const bytes = [];
  while (num > 0n) {
    bytes.push(Number(num & 0xffn));
    num >>= 8n;
  }
  bytes.reverse();
  let leading = 0;
  for (const ch of str) {
    if (ch !== '1') break;
    leading += 1;
  }
  return new Uint8Array([...new Uint8Array(leading), ...bytes]);
}

export function base64Decode(str) {
  if (typeof str !== 'string' || str.length === 0) throw new Error('nep413: base64 input must be a non-empty string');
  return new Uint8Array(Buffer.from(str, 'base64'));
}

function borshString(str) {
  const utf8 = new TextEncoder().encode(str);
  const out = new Uint8Array(4 + utf8.length);
  new DataView(out.buffer).setUint32(0, utf8.length, true);
  out.set(utf8, 4);
  return out;
}

function concatBytes(parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

// The link statement a linked wallet signs. The exact wording is
// part of the proof: verifyLinkSignature checks the message matches
// buildLinkMessage(linked, primary) for the claimed pair, so a
// signature cannot be replayed for a different primary.
export function buildLinkMessage(linked, primary) {
  if (typeof linked !== 'string' || linked.length === 0) throw new Error('nep413: linked must be a non-empty string');
  if (typeof primary !== 'string' || primary.length === 0) throw new Error('nep413: primary must be a non-empty string');
  return `VeilProof link\nLinked wallet: ${linked}\nPrimary wallet: ${primary}`;
}

// Borsh-serialised NEP-413 payload bytes for (message, nonce, recipient).
// nonce is base64 (32 bytes); callbackUrl is always None here.
export function nep413PayloadBytes(message, nonceB64, recipient) {
  if (typeof message !== 'string' || message.length === 0) throw new Error('nep413: message must be a non-empty string');
  if (typeof recipient !== 'string' || recipient.length === 0) throw new Error('nep413: recipient must be a non-empty string');
  const nonce = base64Decode(nonceB64);
  if (nonce.length !== 32) throw new Error('nep413: nonce must be 32 bytes');
  const tag = new Uint8Array(4);
  new DataView(tag.buffer).setUint32(0, NEP413_TAG, true);
  return concatBytes([tag, borshString(message), nonce, borshString(recipient), new Uint8Array([0])]);
}

function parsePublicKey(publicKey) {
  if (typeof publicKey !== 'string' || !publicKey.startsWith('ed25519:')) {
    throw new Error('nep413: publicKey must be an ed25519: base58 key');
  }
  const raw = base58Decode(publicKey.slice('ed25519:'.length));
  if (raw.length !== 32) throw new Error('nep413: publicKey must decode to 32 bytes');
  return raw;
}

// Verify a NEP-413 signature. sig is { message, nonce, recipient,
// signature (base64), publicKey ('ed25519:...') }. Returns true only
// when the signature verifies against the reconstructed payload AND
// the recipient is the VeilProof registry (a signature meant for
// another dApp cannot be replayed here). Never throws for a bad
// signature: malformed inputs return false, except a non-object sig
// which throws (caller error).
export function verifyLinkSignature(sig) {
  if (!sig || typeof sig !== 'object') throw new Error('nep413: signature must be an object');
  try {
    if (sig.recipient !== LINK_RECIPIENT) return false;
    if (typeof sig.signature !== 'string' || typeof sig.publicKey !== 'string') return false;
    const payload = nep413PayloadBytes(sig.message, sig.nonce, sig.recipient);
    const digest = createHash('sha256').update(payload).digest();
    const signature = base64Decode(sig.signature);
    if (signature.length !== 64) return false;
    const publicKey = parsePublicKey(sig.publicKey);
    return nacl.sign.detached.verify(new Uint8Array(digest), signature, publicKey);
  } catch {
    return false;
  }
}

// Sign a link message with a raw ed25519 secret key (Node/testnet
// tooling only — the browser flow uses the wallet's signMessage).
// secretKey is the 64-byte ed25519 secret key. Returns { message,
// nonce, recipient, signature (base64), publicKey ('ed25519:...') }.
export function signLinkMessage(secretKey, linked, primary, nonceB64) {
  if (!(secretKey instanceof Uint8Array) || secretKey.length !== 64) {
    throw new Error('nep413: secretKey must be a 64-byte Uint8Array');
  }
  const message = buildLinkMessage(linked, primary);
  const payload = nep413PayloadBytes(message, nonceB64, LINK_RECIPIENT);
  const digest = createHash('sha256').update(payload).digest();
  const keyPair = nacl.sign.keyPair.fromSecretKey(secretKey);
  const signature = nacl.sign.detached(new Uint8Array(digest), keyPair.secretKey);
  return {
    message,
    nonce: nonceB64,
    recipient: LINK_RECIPIENT,
    signature: Buffer.from(signature).toString('base64'),
    publicKey: `ed25519:${base58Encode(keyPair.publicKey)}`,
  };
}

export function base58Encode(bytes) {
  if (!(bytes instanceof Uint8Array)) throw new Error('nep413: base58 input must be a Uint8Array');
  let num = 0n;
  for (const b of bytes) num = (num << 8n) + BigInt(b);
  let out = '';
  while (num > 0n) {
    out = BASE58_ALPHABET[Number(num % 58n)] + out;
    num /= 58n;
  }
  let leading = 0;
  for (const b of bytes) {
    if (b !== 0) break;
    leading += 1;
  }
  return '1'.repeat(leading) + out;
}
