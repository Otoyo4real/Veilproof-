// NEP-413 signed messages, for the signature link proof — browser
// mirror of src/nep413.js. Same payload construction and verification,
// but SHA-256 uses Web Crypto (async), so verifyLinkSignature is
// async here. ed25519 uses the vendored tweetnacl global
// (public/js/nacl.min.js, loaded by a <script> tag before this
// module); the Node module imports the same library from npm, so the
// two paths agree exactly.
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
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
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

export function buildLinkMessage(linked, primary) {
  if (typeof linked !== 'string' || linked.length === 0) throw new Error('nep413: linked must be a non-empty string');
  if (typeof primary !== 'string' || primary.length === 0) throw new Error('nep413: primary must be a non-empty string');
  return `VeilProof link\nLinked wallet: ${linked}\nPrimary wallet: ${primary}`;
}

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

// Verify a NEP-413 signature (async: Web Crypto for SHA-256). sig is
// { message, nonce, recipient, signature (base64), publicKey
// ('ed25519:...') }. Returns true only when the signature verifies
// against the reconstructed payload AND the recipient is the
// VeilProof registry. Never throws for a bad signature: malformed
// inputs return false, except a non-object sig which throws.
export async function verifyLinkSignature(sig) {
  if (!sig || typeof sig !== 'object') throw new Error('nep413: signature must be an object');
  try {
    if (sig.recipient !== LINK_RECIPIENT) return false;
    if (typeof sig.signature !== 'string' || typeof sig.publicKey !== 'string') return false;
    const payload = nep413PayloadBytes(sig.message, sig.nonce, sig.recipient);
    const digest = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', payload));
    const signature = base64Decode(sig.signature);
    if (signature.length !== 64) return false;
    const publicKey = parsePublicKey(sig.publicKey);
    const nacl = globalThis.nacl;
    if (!nacl || !nacl.sign || !nacl.sign.detached || typeof nacl.sign.detached.verify !== 'function') {
      throw new Error('nep413: tweetnacl (nacl.min.js) is not loaded');
    }
    return nacl.sign.detached.verify(digest, signature, publicKey);
  } catch {
    return false;
  }
}
