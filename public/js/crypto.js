// VeilProof browser crypto — Web Crypto only.
//
// This is the browser replacement for the two node:crypto uses in
// src/report.js, src/disclosure.js and src/onchain.js: SHA-256 hex and
// random bytes. It references globalThis.crypto so the same file runs
// in a browser secure context AND in Node's test environment (Node >= 19
// exposes globalThis.crypto.subtle and getRandomValues).
//
// There is no Node counterpart file for this one: it is the browser's
// hash primitive, and the parity test checks its outputs against
// node:crypto on identical inputs.

export async function sha256Hex(str) {
  const c = globalThis.crypto;
  if (!c || !c.subtle) {
    throw new Error('sha256Hex: Web Crypto (crypto.subtle) is unavailable, use a secure context (https or localhost)');
  }
  const buf = await c.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function randomHex(byteCount) {
  const c = globalThis.crypto;
  if (!c || !c.getRandomValues) {
    throw new Error('randomHex: crypto.getRandomValues is unavailable, use a secure context (https or localhost)');
  }
  const bytes = new Uint8Array(byteCount);
  c.getRandomValues(bytes);
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}
