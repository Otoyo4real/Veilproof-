// Shared attestation fixture builder for the attestation tests.
//
// The fixture is REAL NEAR AI Cloud evidence (test/fixtures/
// near-ai-attestation.json): gateway + model reports fetched live on
// 2026-11-06 for z-ai/glm-5.3-flash, with the TD values @phala/dcap-qvl
// returned for those quotes (status UpToDate, no advisories) recorded
// alongside. The stub dcap below stands in ONLY for the Intel DCAP
// chain (collateral fetch + quote verification against Intel's root):
// it returns exactly those recorded TD values for the fixture quotes.
// Every other check — nonce binding, signer binding, echoed fields,
// RTMR3 replay, MRCONFIGID, model identity, measurements, response
// signatures — runs for real against this evidence.
//
// Two deliberate deviations from the live quotes, both documented:
//   1. The stub recomputes reportData from the evidence's
//      signing_address + the test nonce, so tests can substitute keys
//      they control (the live model/gateway keys are not available).
//      The quote bytes themselves are the real ones and still parse.
//   2. The nvidia_payload / ohttp fields were stripped from the
//      fixture (GPU evidence is recorded, not verified).
//
// This file is a helper, not a test: it exports builders only.

import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak_256 } from '@noble/hashes/sha3';
import nacl from 'tweetnacl';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const FIXTURE_PATH = join(dirname(fileURLToPath(import.meta.url)), 'fixtures', 'near-ai-attestation.json');

export function loadAttestationFixture() {
  return JSON.parse(readFileSync(FIXTURE_PATH, 'utf8'));
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function addressFromPrivateKey(privateKey) {
  const pub = secp256k1.getPublicKey(privateKey, false);
  return `0x${Buffer.from(keccak_256(pub.subarray(1))).subarray(12).toString('hex')}`;
}

function randomPrivateKey() {
  const key = new Uint8Array(32);
  crypto.getRandomValues(key);
  return key;
}

function eip191Hash(text) {
  const textBytes = Buffer.from(text, 'utf8');
  return keccak_256(Buffer.concat([Buffer.from(`\x19Ethereum Signed Message:\n${textBytes.length}`, 'utf8'), textBytes]));
}

// Sign text EIP-191 style (the way the TEE signs response text):
// keccak of the prefixed text, signed directly (no SHA-256 prehash).
// Returns a 65-byte hex signature (r||s||v, v 27/28).
export function signEcdsaText(text, privateKey) {
  const hash = eip191Hash(text);
  const compact = secp256k1.sign(hash, privateKey, { prehash: false });
  const expectedAddress = addressFromPrivateKey(privateKey);
  const r = BigInt(`0x${Buffer.from(compact.subarray(0, 32)).toString('hex')}`);
  const s = BigInt(`0x${Buffer.from(compact.subarray(32, 64)).toString('hex')}`);
  for (const bit of [0, 1]) {
    const recovered = new secp256k1.Signature(r, s, bit).recoverPublicKey(hash);
    const raw = Buffer.from(recovered.toBytes(false));
    const address = `0x${Buffer.from(keccak_256(raw.subarray(1))).subarray(12).toString('hex')}`;
    if (address === expectedAddress) {
      return Buffer.concat([Buffer.from(compact), Buffer.from([bit + 27])]).toString('hex');
    }
  }
  throw new Error('attestation-fixture: could not find the recovery bit');
}

// Sign text the way the TEE signs response text, for a test key:
//   ecdsa: EIP-191 (keccak of the prefixed text, signed directly — no
//     SHA-256 prehash). Returns a 65-byte hex signature (r||s||v).
//   ed25519: detached signature over the UTF-8 text bytes. Returns a
//     64-byte hex signature.
export function signText(text, key) {
  if (key.algo === 'ed25519') {
    return Buffer.from(nacl.sign.detached(Buffer.from(text, 'utf8'), key.privateKey)).toString('hex');
  }
  return signEcdsaText(text, key.privateKey);
}

function paddedIdentity(signingAddress) {
  const bytes = Buffer.from(signingAddress.replace(/^0x/, ''), 'hex');
  return Buffer.concat([bytes, Buffer.alloc(32 - bytes.length, 0)]);
}

// Build a coherent attestation fixture for one nonce/model pair.
// Options:
//   nonce: 64-hex client nonce (default: the fixture's live nonce).
//   model: canonical model id (default: the fixture's model).
//   gatewayKey / modelKey: true to generate a fresh test keypair for
//     that report's signing_address, { privateKey, address } to use a
//     given one, or absent to keep the live address.
//   tcbStatus / advisoryIds: what the stub DCAP reports (default
//     UpToDate / []).
// Returns { nonce, model, evidence, dcap, keys } where keys.gateway /
// keys.model are { privateKey, address } when a test key was generated
// or supplied, and null when the live address was kept.
export function buildAttestationFixture(options = {}) {
  const raw = loadAttestationFixture();
  const nonce = options.nonce ?? raw.nonce;
  const model = options.model ?? raw.model;
  const tcbStatus = options.tcbStatus ?? 'UpToDate';
  const advisoryIds = options.advisoryIds ?? [];

  const keys = { gateway: null, model: null };
  function resolveKey(option, liveAddress, liveAlgo) {
    if (option === true) {
      const privateKey = randomPrivateKey();
      return { algo: 'ecdsa', privateKey, address: addressFromPrivateKey(privateKey) };
    }
    if (option === 'ed25519') {
      const pair = nacl.sign.keyPair();
      return { algo: 'ed25519', privateKey: pair.secretKey, address: Buffer.from(pair.publicKey).toString('hex') };
    }
    if (option && typeof option === 'object') return option;
    return { algo: liveAlgo, privateKey: null, address: liveAddress };
  }
  const gatewayKey = resolveKey(options.gatewayKey, raw.gateway.report.signing_address, raw.gateway.report.signing_algo);
  const modelKey = resolveKey(options.modelKey, raw.modelReport.report.signing_address, raw.modelReport.report.signing_algo);
  if (options.gatewayKey) keys.gateway = gatewayKey;
  if (options.modelKey) keys.model = modelKey;

  const gatewayReport = clone(raw.gateway.report);
  gatewayReport.request_nonce = nonce;
  gatewayReport.signing_address = gatewayKey.address;
  gatewayReport.signing_algo = gatewayKey.algo;
  // The echoed report_data must bind the same identity + nonce as the
  // stub's verified quote, or the echo check (rightly) fails.
  if (typeof gatewayReport.report_data === 'string') {
    gatewayReport.report_data = Buffer.concat([paddedIdentity(gatewayKey.address), Buffer.from(nonce, 'hex')]).toString('hex');
  }
  const modelReport = clone(raw.modelReport.report);
  modelReport.request_nonce = nonce;
  modelReport.signing_address = modelKey.address;
  modelReport.signing_algo = modelKey.algo;
  modelReport.model_name = model;

  const evidence = { gateway_attestation: gatewayReport, model_attestations: [modelReport] };

  // Stub DCAP: returns the recorded TD values for the fixture quotes,
  // with reportData recomputed from the evidence's signing identity +
  // the test nonce (see the header note). Any other quote fails.
  const byQuoteHex = new Map();
  for (const [role, entry, key] of [
    ['gateway', raw.gateway, gatewayKey],
    ['model', raw.modelReport, modelKey],
  ]) {
    const verified = entry.verified;
    const reportData = Buffer.concat([paddedIdentity(key.address), Buffer.from(nonce, 'hex')]);
    const tdFields = {
      tdAttributes: Buffer.from(verified.tdAttributes, 'hex'),
      mrTd: Buffer.from(verified.mrTd, 'hex'),
      mrConfigId: Buffer.from(verified.mrConfigId, 'hex'),
      mrOwner: Buffer.from(verified.mrOwner, 'hex'),
      mrOwnerConfig: Buffer.from(verified.mrOwnerConfig, 'hex'),
      rtMr0: Buffer.from(verified.rtMr0, 'hex'),
      rtMr1: Buffer.from(verified.rtMr1, 'hex'),
      rtMr2: Buffer.from(verified.rtMr2, 'hex'),
      rtMr3: Buffer.from(verified.rtMr3, 'hex'),
      reportData,
    };
    byQuoteHex.set(entry.report.intel_quote.toLowerCase(), {
      role,
      tdFields,
      report: { type: 'td10', asTd10: () => tdFields },
    });
  }
  const dcap = {
    getCollateral: async () => ({}),
    verify: (quoteBytes) => {
      const hex = Buffer.from(quoteBytes).toString('hex').toLowerCase();
      const found = byQuoteHex.get(hex);
      if (!found) throw new Error('stub dcap: unknown quote');
      return { status: tcbStatus, advisory_ids: [...advisoryIds], report: found.report };
    },
  };

  return { nonce, model, evidence, dcap, keys, raw };
}

export function sha256Hex(data) {
  return createHash('sha256').update(data).digest('hex');
}
