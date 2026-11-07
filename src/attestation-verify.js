// VeilProof NEAR AI Cloud attestation verification.
//
// Implements the OFFICIAL verification procedure from docs.near.ai
// (verified 2026-11-06), for evidence returned by
// GET /v1/attestation/report and signatures from GET /v1/signature:
//
//   1. DCAP quote verification with the official verifier approach:
//      @phala/dcap-qvl (pure-JS port of Intel's DCAP Quote Verification
//      Library), collateral from the Phala PCCS by default (Intel PCS
//      via VEILPROOF_ATTESTATION_PCCS_URL), plus a TCB/advisory policy.
//   2. Nonce + signing-identity binding read from the VERIFIED quote's
//      report_data — never from HTTP-echoed fields alone. The echoed
//      request_nonce / report_data are consistency checks against the
//      quote, not a substitute for it.
//   3. RTMR3 event-log replay (SHA-384 chain over imr=3 events).
//   4. MRCONFIGID check: 01 || SHA-256(raw app_compose) || 15 zero
//      bytes, where app_compose is hashed exactly as returned, without
//      parsing or reserialising it.
//   5. Signing-identity check (signing_address + signing_algo together).
//   6. Measurement recording + an optional allowlist policy.
//   7. Model-identity check (model_attestations[].model_name).
//   8. Response-signature verification against the EXACT request and
//      response bytes, bound to the completion id, with the signer
//      matched to exactly one verified preflight report.
//
// Four attestation states, and only four:
//
//   VERIFIED   — every required cryptographic check passed.
//   UNVERIFIED — evidence missing, or verification could not be
//                completed (collateral unavailable, malformed evidence,
//                signature unavailable, ambiguous signer match).
//   FAILED     — a cryptographic check failed (bad quote, TCB rejected,
//                nonce/signer not bound in the verified quote, RTMR3
//                or MRCONFIGID mismatch, signature recovery/text
//                mismatch, replayed nonce).
//   EXPIRED    — a previously VERIFIED result evaluated after its
//                validity window (default 60 minutes, matching the
//                official SDK's deployment-verification cache).
//
// Never accept an arbitrary JSON "verified" field as proof, and never
// use a locally calculated SHA-256 hash as a substitute for signature
// verification. The evidence content hash (ref, computed by the caller
// in src/ai-analysis.js) pins WHICH evidence was checked; it proves
// nothing about the evidence itself.
//
// What this does NOT establish (documented in
// docs/attestation-verification.md, do not claim otherwise):
//   - a complete end-to-end chain from model execution through gateway
//     processing to the final bytes. The verified preflight evidence
//     and the one response signature do not form that chain.
//   - that the completion came from the same serving instance as the
//     verified report: instances of the same model share one signing
//     key, so a matching provider_tee signer proves the model TEE
//     family, not the instance.
//   - GPU evidence: nvidia_payload is recorded (presence + nonce
//     match) but NOT verified against NVIDIA NRAS and NOT required.
//   - TLS binding: the peer certificate SPKI is not bound to the
//     quote (no include_tls_fingerprint request is made).
//   - image provenance: measurements are recorded and can be
//     allowlisted, but no Sigstore provenance check runs by default.
//
// Policy (env, all optional; resolveAttestationPolicy reads them):
//   VEILPROOF_ATTESTATION_TCB_ACCEPT        default "UpToDate,OutOfDate"
//     Accepted Intel TCB statuses. This matches the official SDK's
//     documented policy (accepts UpToDate and OutOfDate); advisory IDs
//     are reported in the result, not individually allowlisted.
//   VEILPROOF_ATTESTATION_MAX_AGE_MS        default 3600000 (60 min)
//     Validity window of a VERIFIED result; past it the result is
//     EXPIRED.
//   VEILPROOF_ATTESTATION_MEASUREMENTS      default unset
//     JSON array of { mrtd, mrconfigid?, composeHash? } (hex). When
//     set, the verified measurements must match an entry or the report
//     FAILS. When unset, measurements are checked for internal
//     consistency (RTMR3 replay + MRCONFIGID) and recorded, and the
//     result reports measurementsAllowlisted: false.
//   VEILPROOF_ATTESTATION_REQUIRE_MODEL      default "true"
//     Reject a missing/empty model_attestations[].
//   VEILPROOF_ATTESTATION_REQUIRE_SIGNATURE  default "true"
//     A VERIFIED result requires a verified response signature.
//   VEILPROOF_ATTESTATION_REQUIRE_GPU        default "false"
//     GPU evidence is not required (see above).
//   VEILPROOF_ATTESTATION_PCCS_URL           default Phala PCCS
//     Collateral source for dcap-qvl (set to Intel PCS to use Intel's).
//   VEILPROOF_ATTESTATION_SIGNATURE_RETRIES  default 5
//   VEILPROOF_ATTESTATION_SIGNATURE_RETRY_DELAY_MS  default 1000
//     Bounded retries for GET /v1/signature on 404 (the signature is
//     cached on the serving node and may transiently 404).
//
// The DCAP implementation is injectable ({ getCollateral, verify })
// so tests can stand in for the Intel chain while every other check
// runs for real. The default is the real @phala/dcap-qvl.
//
// Key handling: this module never reads, logs, or returns any API key.
// The signature fetch needs the caller's key; it is passed in by
// src/ai-analysis.js, which reads it from env server-side only.

import { createHash } from 'node:crypto';
import { Quote, getCollateral, verify as verifyDcapQuote } from '@phala/dcap-qvl';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { keccak_256 } from '@noble/hashes/sha3';
import nacl from 'tweetnacl';

export const ATTESTATION_STATUSES = ['VERIFIED', 'UNVERIFIED', 'FAILED', 'EXPIRED'];
export const DEFAULT_TCB_ACCEPTED = ['UpToDate', 'OutOfDate'];
export const DEFAULT_MAX_EVIDENCE_AGE_MS = 60 * 60 * 1000;
export const DEFAULT_SIGNATURE_RETRIES = 5;
export const DEFAULT_SIGNATURE_RETRY_DELAY_MS = 1000;
export const DEFAULT_SIGNING_ALGO = 'ecdsa';
export const DEFAULT_PCCS_URL = 'https://pccs.phala.network/sgx/certification/v4/';

// Method strings carried on results, so a consumer can tell which
// procedure produced the verdict.
export const METHOD_PREFLIGHT = 'near-ai-cloud-dcap';
export const METHOD_FULL = 'near-ai-cloud-dcap+response-signature';

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function shortError(err) {
  return String(err && err.message ? err.message : err).slice(0, 200);
}

export function sha256Hex(data) {
  return createHash('sha256').update(data).digest('hex');
}

function sha384(data) {
  return createHash('sha384').update(data).digest();
}

// --- Policy ------------------------------------------------------------

export function resolveAttestationPolicy(env = process.env) {
  const tcbAccepted = String(env.VEILPROOF_ATTESTATION_TCB_ACCEPT || DEFAULT_TCB_ACCEPTED.join(','))
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  let measurements = null;
  if (typeof env.VEILPROOF_ATTESTATION_MEASUREMENTS === 'string' && env.VEILPROOF_ATTESTATION_MEASUREMENTS.trim() !== '') {
    try {
      const parsed = JSON.parse(env.VEILPROOF_ATTESTATION_MEASUREMENTS);
      if (!Array.isArray(parsed)) throw new Error('must be a JSON array');
      measurements = parsed;
    } catch (err) {
      throw new Error(`VEILPROOF_ATTESTATION_MEASUREMENTS is invalid: ${shortError(err)}`);
    }
  }
  const maxAgeMs = Number(env.VEILPROOF_ATTESTATION_MAX_AGE_MS || DEFAULT_MAX_EVIDENCE_AGE_MS);
  return {
    tcbAccepted: tcbAccepted.length > 0 ? tcbAccepted : [...DEFAULT_TCB_ACCEPTED],
    maxEvidenceAgeMs: Number.isFinite(maxAgeMs) && maxAgeMs > 0 ? maxAgeMs : DEFAULT_MAX_EVIDENCE_AGE_MS,
    measurements,
    requireModel: String(env.VEILPROOF_ATTESTATION_REQUIRE_MODEL ?? 'true').toLowerCase() !== 'false',
    requireSignature: String(env.VEILPROOF_ATTESTATION_REQUIRE_SIGNATURE ?? 'true').toLowerCase() !== 'false',
    requireGpu: String(env.VEILPROOF_ATTESTATION_REQUIRE_GPU ?? 'false').toLowerCase() === 'true',
    pccsUrl: typeof env.VEILPROOF_ATTESTATION_PCCS_URL === 'string' && env.VEILPROOF_ATTESTATION_PCCS_URL.trim() !== ''
      ? env.VEILPROOF_ATTESTATION_PCCS_URL.trim()
      : DEFAULT_PCCS_URL,
    signatureRetries: Math.max(
      1,
      Number(env.VEILPROOF_ATTESTATION_SIGNATURE_RETRIES || DEFAULT_SIGNATURE_RETRIES) || DEFAULT_SIGNATURE_RETRIES,
    ),
    signatureRetryDelayMs: Math.max(
      0,
      Number(env.VEILPROOF_ATTESTATION_SIGNATURE_RETRY_DELAY_MS || DEFAULT_SIGNATURE_RETRY_DELAY_MS) ||
        DEFAULT_SIGNATURE_RETRY_DELAY_MS,
    ),
  };
}

// --- Replay protection: used nonces ------------------------------------
// A nonce is single-use: evidence carrying a nonce that already
// verified once is a replay and FAILS. The store is in-memory and
// per-process (a serverless instance holds its own); entries older
// than maxAgeMs are pruned on every access. This is replay protection
// for the evidence presented to this process, not a global registry.

export function createNonceStore(maxAgeMs = DEFAULT_MAX_EVIDENCE_AGE_MS) {
  const seen = new Map(); // nonce hex -> timestamp ms
  function prune(nowMs) {
    for (const [nonce, at] of seen) {
      if (nowMs - at > maxAgeMs) seen.delete(nonce);
    }
  }
  return {
    has(nonce, nowMs = Date.now()) {
      prune(nowMs);
      return seen.has(nonce);
    },
    add(nonce, nowMs = Date.now()) {
      prune(nowMs);
      seen.set(nonce, nowMs);
    },
    size(nowMs = Date.now()) {
      prune(nowMs);
      return seen.size;
    },
  };
}

export const defaultNonceStore = createNonceStore();

// --- Pure helpers (exported for tests) ---------------------------------

function decodeHex(value, label) {
  if (typeof value !== 'string' || !/^(0x)?[0-9a-fA-F]*$/.test(value) || value.replace(/^0x/, '').length % 2 !== 0) {
    throw new Error(`${label} is not a hex string`);
  }
  return Buffer.from(value.replace(/^0x/, ''), 'hex');
}

// Decode the signing identity the way the quote binds it:
// ecdsa -> a 20-byte Ethereum-style address; ed25519 -> the 32-byte
// public key. Throws on a malformed identity.
export function decodeSigningIdentity(signingAddress, signingAlgo) {
  if (typeof signingAddress !== 'string' || signingAddress.length === 0) {
    throw new Error('signing_address is missing');
  }
  const bytes = decodeHex(signingAddress, 'signing_address');
  if (signingAlgo === 'ecdsa') {
    if (bytes.length !== 20) throw new Error(`ecdsa signing_address must be 20 bytes, got ${bytes.length}`);
    return bytes;
  }
  if (signingAlgo === 'ed25519') {
    if (bytes.length !== 32) throw new Error(`ed25519 signing_address must be 32 bytes, got ${bytes.length}`);
    return bytes;
  }
  throw new Error(`unsupported signing_algo: ${signingAlgo}`);
}

// The first 32 bytes of report_data: the decoded signing identity,
// zero-padded on the right to 32 bytes (no TLS binding requested).
export function expectedReportDataIdentity(signingAddress, signingAlgo) {
  const identity = decodeSigningIdentity(signingAddress, signingAlgo);
  return Buffer.concat([identity, Buffer.alloc(32 - identity.length, 0)]);
}

// Parse an event_log that may arrive as a JSON string (gateway) or
// already parsed (model reports). Must be an array; throws otherwise.
export function parseEventLog(raw) {
  const events = typeof raw === 'string' ? JSON.parse(raw) : raw;
  if (!Array.isArray(events)) throw new Error('event_log is not an array');
  return events;
}

// Replay the RTMR3 event log per the official procedure. Only imr=3
// events, in order:
//   digest = SHA-384(event_type as 4 little-endian bytes || ":"
//                    || event as UTF-8 || ":" || hex-decoded payload)
//   if the event carries a non-empty digest, it must equal the computed
//   one; an empty digest uses the computed one.
//   RTMR3 starts at 48 zero bytes and extends once per event:
//   RTMR3 = SHA-384(RTMR3 || digest).
// Returns the replayed RTMR3 (hex) plus the authenticated imr=3
// payloads (compose-hash, app-id, instance-id, os-image-hash). Throws
// on any malformed event or digest mismatch.
export function replayRtmr3(eventLogRaw) {
  const events = parseEventLog(eventLogRaw);
  let rtmr3 = Buffer.alloc(48, 0);
  let checked = 0;
  let composeHash = null;
  let appId = null;
  let instanceId = null;
  let osImageHash = null;
  for (const event of events) {
    if (!isObject(event) || event.imr !== 3) continue;
    if (typeof event.event_type !== 'number' || !Number.isInteger(event.event_type)) {
      throw new Error('RTMR3 replay: imr=3 event has a non-integer event_type');
    }
    if (typeof event.event !== 'string') throw new Error('RTMR3 replay: imr=3 event has a non-string event name');
    if (typeof event.event_payload !== 'string') throw new Error('RTMR3 replay: imr=3 event has a non-string event_payload');
    const typeBuf = Buffer.alloc(4);
    typeBuf.writeUInt32LE(event.event_type, 0);
    let payloadBytes;
    try {
      payloadBytes = decodeHex(event.event_payload, 'event_payload');
    } catch {
      throw new Error('RTMR3 replay: imr=3 event_payload is not hex');
    }
    const digest = sha384(
      Buffer.concat([typeBuf, Buffer.from(':', 'utf8'), Buffer.from(event.event, 'utf8'), Buffer.from(':', 'utf8'), payloadBytes]),
    );
    if (typeof event.digest === 'string' && event.digest.length > 0) {
      let stated;
      try {
        stated = decodeHex(event.digest, 'event digest');
      } catch {
        throw new Error('RTMR3 replay: imr=3 event digest is not hex');
      }
      if (!stated.equals(digest)) throw new Error('RTMR3 replay: event digest does not match the recomputed digest');
    }
    rtmr3 = sha384(Buffer.concat([rtmr3, digest]));
    checked += 1;
    // Authenticated payloads: recomputing the digest above is what
    // authenticates them, so reading them here is safe.
    if (event.event === 'compose-hash' && payloadBytes.length === 32) composeHash = payloadBytes.toString('hex');
    if (event.event === 'app-id' && payloadBytes.length > 0) appId = payloadBytes.toString('hex');
    if (event.event === 'instance-id' && payloadBytes.length > 0) instanceId = payloadBytes.toString('hex');
    if (event.event === 'os-image-hash' && payloadBytes.length === 32) osImageHash = payloadBytes.toString('hex');
  }
  return { rtmr3: rtmr3.toString('hex'), checked, total: events.length, composeHash, appId, instanceId, osImageHash };
}

// MRCONFIGID is 48 bytes: 0x01, then SHA-256 of the RAW app_compose
// string (hashed exactly as returned, without parsing or
// reserialising it), then 15 zero bytes.
export function checkMrConfigId(mrConfigIdBytes, appCompose) {
  if (!Buffer.isBuffer(mrConfigIdBytes) || mrConfigIdBytes.length !== 48) return false;
  if (typeof appCompose !== 'string') return false;
  const expected = Buffer.concat([
    Buffer.from([0x01]),
    createHash('sha256').update(appCompose, 'utf8').digest(),
    Buffer.alloc(15, 0),
  ]);
  return expected.equals(mrConfigIdBytes);
}

// Read tcb_info, which may itself be JSON text or an already-parsed
// object. Returns the object; throws when it is missing or malformed.
export function parseTcbInfo(info) {
  const raw = isObject(info) ? info.tcb_info : undefined;
  if (raw === undefined || raw === null) throw new Error('tcb_info is missing');
  const parsed = typeof raw === 'string' ? JSON.parse(raw) : raw;
  if (!isObject(parsed)) throw new Error('tcb_info is not an object');
  return parsed;
}

// EIP-191 hash: keccak256("\x19Ethereum Signed Message:\n" + byte
// length + text). NOTE: @noble/curves v2 defaults sign/verify to a
// SHA-256 prehash; recovery below passes the digest directly and
// never lets the library hash again.
export function eip191Hash(text) {
  const textBytes = Buffer.from(text, 'utf8');
  return keccak_256(Buffer.concat([Buffer.from(`\x19Ethereum Signed Message:\n${textBytes.length}`, 'utf8'), textBytes]));
}

// Recover the Ethereum-style signing address of an ECDSA (EIP-191
// personal_sign) signature. The signature is 65 bytes r||s||v, hex
// (with or without 0x), v in 27/28 (or 0/1). Returns a lowercase
// 0x-address. Throws on a malformed signature or an unrecoverable one.
export function recoverEcdsaAddress(text, signatureHex) {
  const sig = decodeHex(signatureHex, 'signature');
  if (sig.length !== 65) throw new Error(`ecdsa signature must be 65 bytes, got ${sig.length}`);
  const r = BigInt(`0x${sig.subarray(0, 32).toString('hex')}`);
  const s = BigInt(`0x${sig.subarray(32, 64).toString('hex')}`);
  let v = sig[64];
  if (v === 27 || v === 28) v -= 27;
  if (v !== 0 && v !== 1) throw new Error(`ecdsa signature has an unsupported recovery byte: ${sig[64]}`);
  const hash = eip191Hash(text);
  let point;
  try {
    point = new secp256k1.Signature(r, s, v).recoverPublicKey(hash);
  } catch (err) {
    throw new Error(`ecdsa recovery failed: ${shortError(err)}`);
  }
  const uncompressed = Buffer.from(point.toBytes(false));
  const address = Buffer.from(keccak_256(uncompressed.subarray(1))).subarray(12).toString('hex');
  return `0x${address}`;
}

// Verify an ed25519 signature over the UTF-8 bytes of text, using the
// signing_address (32-byte public key, hex) as the key. Returns a
// boolean; throws on malformed inputs.
export function verifyEd25519Signature(text, signatureHex, publicKeyHex) {
  const signature = decodeHex(signatureHex, 'signature');
  if (signature.length !== 64) throw new Error(`ed25519 signature must be 64 bytes, got ${signature.length}`);
  const publicKey = decodeHex(publicKeyHex, 'public key');
  if (publicKey.length !== 32) throw new Error(`ed25519 public key must be 32 bytes, got ${publicKey.length}`);
  return nacl.sign.detached.verify(Buffer.from(text, 'utf8'), signature, publicKey);
}

// The exact text a response signature must carry:
//   provider_tee: "<MODEL_ID>:<request_hash>:<response_hash>"
//   gateway:      "<request_hash>:<response_hash>"
// where the hashes are SHA-256 hex of the exact request/response bytes.
export function expectedSignatureText(kind, model, requestHash, responseHash) {
  if (kind === 'provider_tee') return `${model}:${requestHash}:${responseHash}`;
  if (kind === 'gateway') return `${requestHash}:${responseHash}`;
  throw new Error(`unknown signature kind: ${kind}`);
}

// --- DCAP quote verification -------------------------------------------
// The default dcap implementation is the real @phala/dcap-qvl:
// getCollateral fetches PCK/TCB/QE collateral from the PCCS (network
// failures surface here), verify checks the quote against it (crypto
// failures surface here). Splitting the two is what lets the caller
// tell "verifier unavailable" (UNVERIFIED) from "quote failed"
// (FAILED) without string-matching error messages.

export const defaultDcap = {
  getCollateral: (pccsUrl, quoteBytes) => getCollateral(pccsUrl, quoteBytes),
  verify: (quoteBytes, collateral, nowSecs) => verifyDcapQuote(quoteBytes, collateral, nowSecs),
};

export async function verifyQuoteDcap(quoteBytes, { dcap = defaultDcap, pccsUrl = DEFAULT_PCCS_URL, nowMs = Date.now() } = {}) {
  try {
    Quote.parse(quoteBytes);
  } catch (err) {
    return { ok: false, kind: 'failed', check: 'quote-parse', error: `quote does not parse: ${shortError(err)}` };
  }
  let collateral;
  try {
    collateral = await dcap.getCollateral(pccsUrl, quoteBytes);
  } catch (err) {
    return { ok: false, kind: 'unavailable', check: 'collateral', error: `quote collateral unavailable: ${shortError(err)}` };
  }
  let verified;
  try {
    verified = dcap.verify(quoteBytes, collateral, Math.floor(nowMs / 1000));
  } catch (err) {
    return { ok: false, kind: 'failed', check: 'quote-verify', error: `DCAP quote verification failed: ${shortError(err)}` };
  }
  return {
    ok: true,
    status: verified.status,
    advisoryIds: Array.isArray(verified.advisory_ids) ? verified.advisory_ids : [],
    report: verified.report,
  };
}

// --- One attestation report (gateway or one model candidate) ------------
// Runs every check the official procedure requires for one report.
// Returns a plain result object; never throws for bad evidence
// (only a malformed options object throws). outcome is 'verified' |
// 'failed' | 'unverified'.

export async function verifyAttestationReport(
  report,
  { role, nonce, model, policy, dcap = defaultDcap, nowMs = Date.now() } = {},
) {
  if (role !== 'gateway' && role !== 'model') throw new Error('verifyAttestationReport: role must be gateway or model');
  if (typeof nonce !== 'string' || !/^[0-9a-fA-F]{64}$/.test(nonce)) {
    throw new Error('verifyAttestationReport: nonce must be 64 hex characters');
  }
  const checks = {};
  const fail = (check, error) => ({ role, outcome: 'failed', check, error, checks });
  const unv = (check, error) => ({ role, outcome: 'unverified', check, error, checks });

  if (!isObject(report)) return unv('shape', 'report is not an object');
  if (typeof report.intel_quote !== 'string' || report.intel_quote.length === 0) {
    return unv('shape', 'intel_quote is missing');
  }
  if (typeof report.signing_address !== 'string' || report.signing_address.length === 0) {
    return unv('shape', 'signing_address is missing');
  }
  if (report.signing_algo !== 'ecdsa' && report.signing_algo !== 'ed25519') {
    return unv('shape', `signing_algo is missing or unsupported: ${String(report.signing_algo)}`);
  }
  if (typeof report.request_nonce !== 'string' || report.request_nonce.length === 0) {
    return unv('shape', 'request_nonce is missing');
  }

  let quoteBytes;
  try {
    quoteBytes = decodeHex(report.intel_quote, 'intel_quote');
  } catch {
    return unv('quote-encoding', 'intel_quote is not a hex string');
  }

  const dcapResult = await verifyQuoteDcap(quoteBytes, { dcap, pccsUrl: policy.pccsUrl, nowMs });
  if (!dcapResult.ok) {
    if (dcapResult.kind === 'unavailable') return unv(dcapResult.check, dcapResult.error);
    return fail(dcapResult.check, dcapResult.error);
  }
  checks.dcap = { status: dcapResult.status, advisoryIds: dcapResult.advisoryIds };
  const td = dcapResult.report && typeof dcapResult.report.asTd10 === 'function' ? dcapResult.report.asTd10() : null;
  if (!td) return fail('quote-report', 'verified quote is not a TDX report');
  checks.quoteType = dcapResult.report.type ?? 'tdx';

  // TDX debug mode is rejected by dcap-qvl already; check explicitly
  // so the reason is visible in the result either way.
  const tdAttributes = Buffer.from(td.tdAttributes);
  if (tdAttributes.length < 1 || (tdAttributes[0] & 1) !== 0) {
    return fail('debug-mode', 'TDX debug mode is enabled in the verified quote');
  }
  checks.debugMode = false;

  if (!policy.tcbAccepted.includes(dcapResult.status)) {
    return fail(
      'tcb-policy',
      `TCB status ${dcapResult.status} is not accepted (accepted: ${policy.tcbAccepted.join(', ')}); advisories: ${
        dcapResult.advisoryIds.length > 0 ? dcapResult.advisoryIds.join(', ') : 'none'
      }`,
    );
  }
  checks.tcbStatus = dcapResult.status;
  checks.advisoryIds = dcapResult.advisoryIds;

  // Nonce + signer binding, read from the VERIFIED quote's report_data.
  const reportData = Buffer.from(td.reportData);
  if (reportData.length !== 64) return fail('report-data', 'verified quote report_data is not 64 bytes');
  const nonceBytes = Buffer.from(nonce, 'hex');
  if (!reportData.subarray(32).equals(nonceBytes)) {
    return fail('nonce-binding', 'verified quote report_data does not contain the client nonce');
  }
  checks.nonceBound = true;
  let expectedIdentity;
  try {
    expectedIdentity = expectedReportDataIdentity(report.signing_address, report.signing_algo);
  } catch (err) {
    return fail('signing-identity', shortError(err));
  }
  if (!reportData.subarray(0, 32).equals(expectedIdentity)) {
    return fail('signer-binding', 'verified quote report_data does not bind the reported signing identity');
  }
  checks.signerBound = true;

  // Echoed fields are consistency checks against the verified quote.
  if (report.request_nonce !== nonce) {
    return fail('echoed-nonce', 'echoed request_nonce does not match the client nonce');
  }
  checks.echoedNonce = true;
  if (typeof report.report_data === 'string' && report.report_data.length > 0) {
    if (report.report_data.toLowerCase() !== reportData.toString('hex')) {
      return fail('echoed-report-data', 'echoed report_data differs from the verified quote');
    }
    checks.echoedReportData = true;
  }

  // RTMR3 event-log replay.
  let replay;
  try {
    replay = replayRtmr3(report.event_log);
  } catch (err) {
    return fail('rtmr3-replay', shortError(err));
  }
  if (replay.rtmr3 !== Buffer.from(td.rtMr3).toString('hex')) {
    return fail('rtmr3-replay', 'replayed event log does not match the quote RTMR3');
  }
  checks.rtmr3Replayed = true;
  checks.rtmr3Events = replay.checked;

  // MRCONFIGID from the raw app_compose string.
  let tcbInfo;
  try {
    tcbInfo = parseTcbInfo(report.info);
  } catch (err) {
    return fail('tcb-info', shortError(err));
  }
  if (typeof tcbInfo.app_compose !== 'string' || tcbInfo.app_compose.length === 0) {
    return fail('mrconfigid', 'tcb_info.app_compose is missing');
  }
  if (!checkMrConfigId(Buffer.from(td.mrConfigId), tcbInfo.app_compose)) {
    return fail('mrconfigid', 'quote MRCONFIGID does not match SHA-256 of the raw app_compose string');
  }
  checks.mrConfigId = true;
  const appComposeHash = sha256Hex(Buffer.from(tcbInfo.app_compose, 'utf8'));

  // Model identity: the report must name the model that was requested.
  if (role === 'model') {
    if (report.model_name !== model) {
      return fail('model-identity', `model report is for ${String(report.model_name ?? '(unknown)')}, expected ${model}`);
    }
    checks.modelIdentity = true;
  }

  // Measurements: recorded always, cross-checked for consistency, and
  // allowlisted when a policy allowlist is configured.
  const measurements = {
    mrtd: Buffer.from(td.mrTd).toString('hex'),
    mrconfigid: Buffer.from(td.mrConfigId).toString('hex'),
    rtmr0: Buffer.from(td.rtMr0).toString('hex'),
    rtmr1: Buffer.from(td.rtMr1).toString('hex'),
    rtmr2: Buffer.from(td.rtMr2).toString('hex'),
    rtmr3: Buffer.from(td.rtMr3).toString('hex'),
    composeHash: replay.composeHash,
    appId: replay.appId,
    instanceId: replay.instanceId,
    osImageHash: replay.osImageHash,
    tcbComposeHash: typeof tcbInfo.compose_hash === 'string' ? tcbInfo.compose_hash : null,
  };
  if (replay.composeHash !== null && replay.composeHash !== appComposeHash) {
    return fail('measurements', 'event-log compose-hash differs from SHA-256 of app_compose');
  }
  if (measurements.tcbComposeHash !== null && measurements.tcbComposeHash !== appComposeHash) {
    return fail('measurements', 'tcb_info compose_hash differs from SHA-256 of app_compose');
  }
  let allowlisted = null;
  if (Array.isArray(policy.measurements) && policy.measurements.length > 0) {
    allowlisted = policy.measurements.some(
      (entry) =>
        isObject(entry) &&
        entry.mrtd === measurements.mrtd &&
        (entry.mrconfigid === undefined || entry.mrconfigid === measurements.mrconfigid) &&
        (entry.composeHash === undefined || entry.composeHash === measurements.composeHash),
    );
    if (!allowlisted) {
      return fail('measurements-allowlist', 'verified measurements are not in the configured allowlist');
    }
  }
  checks.measurementsChecked = true;
  checks.measurementsAllowlisted = allowlisted;

  // GPU evidence: recorded, not verified. The payload nonce is checked
  // locally when present; NRAS verification is NOT performed and GPU
  // evidence is NOT required (policy.requireGpu is honoured below in
  // verifyAttestationEvidence). See docs/attestation-verification.md.
  const gpu = { present: false, nonceMatched: null, nrasVerified: false };
  if (report.nvidia_payload !== undefined && report.nvidia_payload !== null) {
    gpu.present = true;
    try {
      const payload = typeof report.nvidia_payload === 'string' ? JSON.parse(report.nvidia_payload) : report.nvidia_payload;
      gpu.nonceMatched =
        isObject(payload) && typeof payload.nonce === 'string' ? payload.nonce.toLowerCase() === nonce.toLowerCase() : null;
    } catch {
      gpu.nonceMatched = null;
    }
  }

  return {
    role,
    outcome: 'verified',
    signingAddress: report.signing_address,
    signingAlgo: report.signing_algo,
    modelName: typeof report.model_name === 'string' ? report.model_name : null,
    tcbStatus: dcapResult.status,
    advisoryIds: dcapResult.advisoryIds,
    measurements,
    gpu,
    checks,
  };
}

// Strip a per-report result down to the JSON-safe fields a later stage
// (response-signature matching) needs. Drops nothing the matcher uses.
function stripReport(result) {
  if (!result || typeof result !== 'object') return result;
  return {
    role: result.role,
    outcome: result.outcome,
    check: result.check ?? null,
    error: result.error ?? null,
    signingAddress: result.signingAddress ?? null,
    signingAlgo: result.signingAlgo ?? null,
    modelName: result.modelName ?? null,
    tcbStatus: result.tcbStatus ?? null,
    advisoryIds: result.advisoryIds ?? null,
    measurements: result.measurements ?? null,
    gpu: result.gpu ?? null,
    checks: result.checks ?? {},
  };
}

// --- Full preflight evidence -------------------------------------------
// Verifies the gateway report and EVERY model_attestations[] candidate
// for one fresh nonce. Returns the interface the UI consumes:
//
//   { status, method, model, nonceMatched, quoteVerified,
//     signatureVerified: false, measurementsChecked, expiresAt,
//     verifiedAt, details, error? }
//
// signatureVerified is always false here: no completion exists yet.
// Combine with verifyResponseSignature via combineAttestation.

export async function verifyAttestationEvidence(
  evidence,
  { nonce, model, policy, dcap = defaultDcap, nowMs = Date.now(), nonceStore = defaultNonceStore } = {},
) {
  if (typeof nonce !== 'string' || !/^[0-9a-fA-F]{64}$/.test(nonce)) {
    throw new Error('verifyAttestationEvidence: nonce must be 64 hex characters');
  }
  if (typeof model !== 'string' || model.length === 0) {
    throw new Error('verifyAttestationEvidence: model must be a non-empty string');
  }
  const base = {
    method: METHOD_PREFLIGHT,
    model,
    nonceMatched: false,
    quoteVerified: false,
    signatureVerified: false,
    measurementsChecked: false,
    expiresAt: null,
    verifiedAt: null,
    details: {},
    error: undefined,
  };
  if (!isObject(evidence)) {
    return { ...base, status: 'UNVERIFIED', error: 'attestation evidence is not an object' };
  }
  if (nonceStore.has(nonce, nowMs)) {
    return { ...base, status: 'FAILED', error: 'nonce already used: replayed attestation evidence' };
  }
  if (!isObject(evidence.gateway_attestation)) {
    return { ...base, status: 'UNVERIFIED', error: 'gateway attestation is missing' };
  }
  const gateway = await verifyAttestationReport(evidence.gateway_attestation, {
    role: 'gateway',
    nonce,
    model,
    policy,
    dcap,
    nowMs,
  });
  const details = { gateway: stripReport(gateway) };
  if (gateway.outcome !== 'verified') {
    return {
      ...base,
      status: gateway.outcome === 'failed' ? 'FAILED' : 'UNVERIFIED',
      error: `gateway attestation: ${gateway.error}`,
      details,
    };
  }
  const verifiedGateway = { nonceMatched: true, quoteVerified: true, measurementsChecked: true };

  // Model evidence: every returned candidate is verified, none is a
  // substitute for the gateway quote. Missing/empty is rejected when
  // the policy requires model evidence.
  const candidates = evidence.model_attestations;
  if (policy.requireModel && (!Array.isArray(candidates) || candidates.length === 0)) {
    return {
      ...base,
      ...verifiedGateway,
      status: 'UNVERIFIED',
      error: 'model attestation is missing: model_attestations[] is empty or absent',
      details,
    };
  }
  const models = [];
  let firstProblem = null;
  let anyFailed = false;
  if (Array.isArray(candidates)) {
    for (const candidate of candidates) {
      const result = await verifyAttestationReport(candidate, { role: 'model', nonce, model, policy, dcap, nowMs });
      models.push(stripReport(result));
      if (result.outcome !== 'verified') {
        anyFailed = anyFailed || result.outcome === 'failed';
        if (firstProblem === null) firstProblem = `model attestation: ${result.error}`;
      }
    }
  }
  details.models = models;
  if (firstProblem !== null) {
    return {
      ...base,
      ...verifiedGateway,
      status: anyFailed ? 'FAILED' : 'UNVERIFIED',
      error: firstProblem,
      details,
    };
  }
  if (policy.requireGpu) {
    const gpuChecked = models.length > 0 && models.every((m) => m.gpu && m.gpu.present && m.gpu.nonceMatched === true);
    if (!gpuChecked) {
      return {
        ...base,
        ...verifiedGateway,
        status: 'UNVERIFIED',
        error: 'GPU evidence is required by policy but missing or its nonce does not match',
        details,
      };
    }
  }

  const verifiedAt = nowMs;
  const expiresAt = new Date(verifiedAt + policy.maxEvidenceAgeMs).toISOString();
  nonceStore.add(nonce, nowMs);
  return {
    ...base,
    ...verifiedGateway,
    status: 'VERIFIED',
    verifiedAt: new Date(verifiedAt).toISOString(),
    expiresAt,
    details,
  };
}

// Re-evaluate a previously produced result against the clock. A
// VERIFIED result past its expiresAt is EXPIRED; anything else stands.
export function attestationStatusAt(result, nowMs = Date.now()) {
  if (!result || typeof result !== 'object') return 'UNVERIFIED';
  if (result.status === 'VERIFIED' && typeof result.expiresAt === 'string' && nowMs > Date.parse(result.expiresAt)) {
    return 'EXPIRED';
  }
  return ATTESTATION_STATUSES.includes(result.status) ? result.status : 'UNVERIFIED';
}

// --- Response-signature verification -----------------------------------
// Fetches GET /v1/signature/{completionId} and verifies it against the
// exact request/response bytes and the VERIFIED preflight evidence.
// Returns { status, kind, signer, textMatched, signerMatched,
// signatureVerified, error? }. status is VERIFIED only when the text
// matches the exact bytes AND the signer recovers/verifies AND matches
// exactly one verified preflight report for that kind.
//
// A 404 means no matching signature was found; it is retried for a
// short bounded interval (the signature is cached on the serving
// node). A successful 2xx carrying error_code/message is an
// unavailable result, not a signature. Either way the response is
// UNVERIFIED when a signature is required — never VERIFIED.

export async function verifyResponseSignature({
  fetchImpl,
  base,
  completionId,
  model,
  signingAlgo,
  apiKey,
  requestBytes,
  responseBytes,
  preflight,
  policy,
}) {
  const result = {
    kind: null,
    signer: null,
    textMatched: false,
    signerMatched: false,
    signatureVerified: false,
    status: 'UNVERIFIED',
    error: undefined,
  };
  if (typeof fetchImpl !== 'function') return { ...result, error: 'no fetch implementation available' };
  if (!preflight || preflight.status !== 'VERIFIED') {
    return { ...result, error: 'preflight evidence is not verified, so no response signature can be matched to it' };
  }
  if (typeof completionId !== 'string' || completionId.length === 0) {
    return { ...result, error: 'completion id is missing, so no signature can be fetched' };
  }
  if (!Buffer.isBuffer(requestBytes) || !Buffer.isBuffer(responseBytes)) {
    return { ...result, error: 'exact request/response bytes are missing' };
  }
  const requestHash = sha256Hex(requestBytes);
  const responseHash = sha256Hex(responseBytes);
  const url =
    `${base}/signature/${encodeURIComponent(completionId)}` +
    `?model=${encodeURIComponent(model)}&signing_algo=${encodeURIComponent(signingAlgo)}`;

  let sigBody = null;
  let lastStatus = null;
  for (let attempt = 1; attempt <= policy.signatureRetries; attempt += 1) {
    let res;
    try {
      res = await fetchImpl(url, {
        method: 'GET',
        headers: { Authorization: `Bearer ${apiKey}`, accept: 'application/json' },
        signal: AbortSignal.timeout(30_000),
      });
    } catch (err) {
      return { ...result, error: `signature fetch failed: ${shortError(err)}` };
    }
    lastStatus = res.status;
    if (res.ok) {
      try {
        sigBody = await res.json();
      } catch {
        return { ...result, error: 'signature response is not valid JSON' };
      }
      break;
    }
    if (res.status === 404) {
      if (attempt < policy.signatureRetries) {
        await new Promise((resolve) => setTimeout(resolve, policy.signatureRetryDelayMs));
        continue;
      }
      return { ...result, error: `signature unavailable: HTTP 404 after ${policy.signatureRetries} attempts` };
    }
    let detail = '';
    try {
      const body = await res.json();
      if (isObject(body) && (body.error_code || body.message)) {
        detail = `: ${[body.error_code, body.message].filter(Boolean).join(' ')}`;
      }
    } catch {
      // No readable body; the status alone is the detail.
    }
    return { ...result, error: `signature unavailable: HTTP ${res.status}${detail}` };
  }
  if (sigBody === null) {
    return { ...result, error: `signature unavailable: HTTP ${lastStatus} after ${policy.signatureRetries} attempts` };
  }
  if (!isObject(sigBody) || typeof sigBody.text !== 'string' || typeof sigBody.signature !== 'string') {
    return { ...result, error: 'signature response is malformed' };
  }
  const kind = sigBody.signature_kind;
  if (kind !== 'provider_tee' && kind !== 'gateway') {
    return { ...result, error: `unknown signature_kind: ${String(kind)} (signer classification unavailable)` };
  }
  result.kind = kind;
  const parts = sigBody.text.split(':');
  if ((kind === 'provider_tee' && parts.length !== 3) || (kind === 'gateway' && parts.length !== 2)) {
    return { ...result, status: 'FAILED', error: 'signature kind does not match the signed text' };
  }
  const expectedText = expectedSignatureText(kind, model, requestHash, responseHash);
  if (sigBody.text !== expectedText) {
    return {
      ...result,
      status: 'FAILED',
      error: 'signature text does not match the exact request/response bytes (response substitution?)',
    };
  }
  result.textMatched = true;

  // The signer must match exactly one VERIFIED preflight report for
  // this kind: model reports for provider_tee, the gateway report for
  // gateway. A report fetched after the completion is never a
  // substitute; only the retained preflight evidence counts.
  const candidates =
    kind === 'provider_tee'
      ? Array.isArray(preflight.details.models)
        ? preflight.details.models
        : []
      : [preflight.details.gateway];
  if (signingAlgo === 'ecdsa') {
    let signer;
    try {
      signer = recoverEcdsaAddress(sigBody.text, sigBody.signature);
    } catch (err) {
      return { ...result, status: 'FAILED', error: `signature recovery failed: ${shortError(err)}` };
    }
    result.signer = signer;
    if (typeof sigBody.signing_address === 'string' && sigBody.signing_address.length > 0) {
      if (sigBody.signing_address.toLowerCase() !== signer.toLowerCase()) {
        return { ...result, status: 'FAILED', error: 'signature response signing_address differs from the recovered signer' };
      }
    }
  } else if (signingAlgo === 'ed25519') {
    if (typeof sigBody.signing_address !== 'string' || sigBody.signing_address.length === 0) {
      return { ...result, error: 'ed25519 signature response carries no signing_address to verify against' };
    }
    result.signer = sigBody.signing_address;
  } else {
    return { ...result, error: `unsupported signing_algo: ${signingAlgo}` };
  }
  const matches = candidates.filter(
    (c) =>
      c &&
      c.outcome === 'verified' &&
      typeof c.signingAddress === 'string' &&
      c.signingAddress.toLowerCase() === String(result.signer).toLowerCase() &&
      c.signingAlgo === signingAlgo,
  );
  if (matches.length === 0) {
    return { ...result, error: 'signature signer matches no verified preflight report' };
  }
  if (matches.length > 1) {
    return { ...result, error: 'signature signer matches more than one verified preflight report (ambiguous)' };
  }
  result.signerMatched = true;
  if (signingAlgo === 'ed25519') {
    let okSig;
    try {
      okSig = verifyEd25519Signature(sigBody.text, sigBody.signature, result.signer);
    } catch (err) {
      return { ...result, status: 'FAILED', error: `ed25519 verification failed: ${shortError(err)}` };
    }
    if (!okSig) {
      return { ...result, status: 'FAILED', error: 'ed25519 signature does not verify against the matched preflight key' };
    }
  }
  // For ecdsa, recovery plus the unique preflight match IS the
  // verification: the recovered address is the signer, and it is the
  // address bound in the verified quote.
  result.signatureVerified = true;
  return { ...result, status: 'VERIFIED' };
}

// --- Combine preflight + signature into the final verdict ---------------
// VERIFIED only when the preflight is VERIFIED, the evidence is still
// inside its validity window, and (when required) the response
// signature is VERIFIED. A FAILED preflight or signature stands as
// FAILED even if the other stage passed: an unverified anchor cannot
// be rescued by a signature, and a failed signature cannot be rescued
// by verified preflight evidence.

export function combineAttestation(preflight, signature, { nowMs = Date.now(), requireSignature = true } = {}) {
  const base = {
    status: preflight.status,
    method: METHOD_FULL,
    model: preflight.model,
    nonceMatched: preflight.nonceMatched,
    quoteVerified: preflight.quoteVerified,
    signatureVerified: signature?.signatureVerified === true,
    measurementsChecked: preflight.measurementsChecked,
    expiresAt: preflight.expiresAt,
    verifiedAt: preflight.verifiedAt ?? null,
    details: { preflight: preflight.details ?? {}, signature: signature ?? null },
    error: preflight.error,
  };
  if (preflight.status === 'VERIFIED' && typeof preflight.expiresAt === 'string' && nowMs > Date.parse(preflight.expiresAt)) {
    return { ...base, status: 'EXPIRED', error: 'attestation evidence is past its validity period' };
  }
  if (preflight.status !== 'VERIFIED') return base;
  if (!requireSignature) return base;
  if (!signature) return { ...base, status: 'UNVERIFIED', error: 'response signature was not checked' };
  if (signature.status === 'VERIFIED') return base;
  if (signature.status === 'FAILED') return { ...base, status: 'FAILED', error: signature.error };
  return { ...base, status: 'UNVERIFIED', error: signature.error };
}
