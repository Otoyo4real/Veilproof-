// VeilProof NEAR AI analysis — TEE-attested consistency check of claims
// AND advisory underwriting judgment.
//
// Two jobs share this module, both reading ONLY claim-level data:
//
// 1. Consistency (analyseClaims): does each claim agree with the
//    metrics it was evaluated from? The model verifies nothing about
//    the chain — chain truth is verified deterministically by
//    src/verify-report.js (re-fetch + re-run).
// 2. Underwriting (analyseUnderwriting): given the deterministic
//    score (score-v1, recomputable by any verifier) and the same
//    claim-level facts, is this agent a good risk to lend to? The
//    verdict is ADVISORY — it never changes a report's validity, and
//    the deterministic guard can only tighten it (a 'lend' on a thin
//    score < 300 becomes a 'decline'). The score is the verifiable
//    fact; the AI's judgment is the opinion on top of it.
//
// Sanitisation is an allowlist, not a denylist: only the fields named
// in sanitiseClaims / sanitiseMetrics / sanitiseScore ever enter a
// request payload, so a caller cannot leak the address by stuffing it
// into the metrics. The model never sees the wallet address, never
// sees a transaction hash, never sees the raw snapshot.
//
// Attestation follows the OFFICIAL NEAR AI Cloud verification
// procedure (docs.near.ai, implemented in src/attestation-verify.js):
// a preflight GET of /v1/attestation/report with a fresh random nonce
// and provider=near, then full verification of the gateway report and
// EVERY model_attestations[] candidate — DCAP quote verification
// (@phala/dcap-qvl), TCB policy, nonce + signer binding read from the
// VERIFIED quote, RTMR3 event-log replay, MRCONFIGID, model identity,
// measurements — and, after the completion, a response-signature check
// against the EXACT request/response bytes, bound to the completion
// id and matched to exactly one verified preflight report. The result
// is one of VERIFIED / UNVERIFIED / FAILED / EXPIRED; a nonce echo
// alone is UNVERIFIED, never VERIFIED. The full evidence (~300 KB)
// is never stored in the summary; the summary carries only
// attestation.ref, the SHA-256 of the canonical evidence JSON, which
// pins WHICH evidence was checked — it proves nothing about the
// evidence itself. A failed preflight or signature does NOT abort the
// analysis — the completion still runs, but the summary is labelled
// with the real status (never attested on untrusted evidence).
//
// Key handling: the key comes from env VEILPROOF_NEAR_AI_API_KEY ONLY,
// read at call time. Without it the function returns
// { status: 'not_configured', summary: null } and never calls the API
// (fail closed). This module never reads any other key, env var, file,
// or connector — in particular it never touches the Genesis NEAR AI
// key/connector. There is no fallback route (no Pollinations, no
// extractive summary): an unanalysed report stays honestly null.
//
// Return contract: every failure mode is a { status, summary: null }
// object, never a throw — except malformed input (claims not an array,
// a malformed claim, a bad policyVersion), which throws like the rest
// of this codebase. Statuses: 'ok' | 'not_configured' | 'unparseable'
// | 'empty_output' | 'api_error'. A successful summary is a plain
// object, so it is accepted as-is by buildReport's aiSummary:
//   { provider: 'near-ai', model, verdict: 'consistent'|'inconsistent',
//     points: string[], attestation }
// where attestation is the full verification verdict from
// src/attestation-verify.js:
//   { status: 'VERIFIED'|'UNVERIFIED'|'FAILED'|'EXPIRED', method,
//     model, nonceMatched, quoteVerified, signatureVerified,
//     measurementsChecked, expiresAt, details, error?,
//     verifiable, ref }
// verifiable is true only when status is VERIFIED; ref is the
// SHA-256 of the canonical evidence JSON (which evidence was checked,
// not proof). The summary's attestation.ref (or null) is the
// attestationRef to pass to evidenceHash / buildReport.
//
// Model gotcha (from the Genesis worker): the default model reasons
// before answering, so a small max_tokens is spent entirely on
// reasoning and returns empty content. maxTokens is therefore floored
// at 800 — a caller asking for less gets 800, silently and safely.

import { createHash, randomBytes } from 'node:crypto';
import { canonicalJson } from './canonical.js';
import {
  verifyAttestationEvidence,
  verifyResponseSignature,
  combineAttestation,
  resolveAttestationPolicy,
  defaultNonceStore,
  DEFAULT_SIGNING_ALGO,
} from './attestation-verify.js';

export const DEFAULT_MODEL = 'z-ai/glm-5.3-flash';
export const DEFAULT_BASE_URL = 'https://cloud-api.near.ai/v1';

const MIN_MAX_TOKENS = 800;
// Default request size. Live evidence 2026-11-06: 800 tokens returned an
// empty completion for the real demo prompt (the model spends the budget
// reasoning before answering — the same gotcha as the Genesis worker),
// while 4000 returned the full JSON summary. The 800 floor stays.
const DEFAULT_MAX_TOKENS = 4000;
const MAX_POINTS = 10;
const MAX_POINT_LEN = 500;
const ATTESTATION_TIMEOUT_MS = 60_000;
const COMPLETION_TIMEOUT_MS = 120_000;

// Metric keys that may be sent to the model. Everything else — address,
// accountId, tx hashes, snapshots, prover commitments — is dropped.
const ALLOWED_METRIC_KEYS = new Set([
  'balanceYocto',
  'stakedYocto',
  'txCount',
  'successTxCount',
  'failedTxCount',
  'volumeYocto',
  'windowDays',
  'txWindowDays',
  'volumeWindowDays',
  'noFailedWindowDays',
]);

function sha256Hex(str) {
  return createHash('sha256').update(str, 'utf8').digest('hex');
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

// Claims, reduced to exactly the four fields the model may see.
// Mirrors report.js's claim-shape validation; throws on malformed input.
export function sanitiseClaims(claims) {
  if (!Array.isArray(claims)) {
    throw new Error('ai-analysis: claims must be an array');
  }
  return claims.map((claim, index) => {
    if (!isObject(claim)) {
      throw new Error(`ai-analysis: claims[${index}] must be an object`);
    }
    if (typeof claim.id !== 'string' || claim.id.length === 0) {
      throw new Error(`ai-analysis: claims[${index}].id must be a non-empty string`);
    }
    if (typeof claim.passed !== 'boolean') {
      throw new Error(`ai-analysis: claims[${index}].passed must be a boolean`);
    }
    for (const field of ['value', 'threshold']) {
      const v = claim[field];
      if (typeof v !== 'string' && typeof v !== 'number') {
        throw new Error(`ai-analysis: claims[${index}].${field} must be a string or number`);
      }
    }
    return { id: claim.id, passed: claim.passed, value: claim.value, threshold: claim.threshold };
  });
}

// Metrics, reduced to the allowlisted aggregate keys. Any other key —
// including address/accountId/hash/tx/snapshot-shaped data a caller
// passes in — is dropped silently. Only finite numbers and strings
// survive; anything else for an allowed key is dropped too.
export function sanitiseMetrics(metrics) {
  if (metrics === undefined || metrics === null) return {};
  if (!isObject(metrics)) {
    throw new Error('ai-analysis: metrics must be an object when provided');
  }
  const clean = {};
  for (const key of Object.keys(metrics)) {
    if (!ALLOWED_METRIC_KEYS.has(key)) continue;
    const v = metrics[key];
    if (typeof v === 'number' && Number.isFinite(v)) clean[key] = v;
    else if (typeof v === 'string') clean[key] = v;
  }
  return clean;
}

// Deterministic internal-consistency check of the claims, independent
// of the model. Returns { consistent, problems }. Only invariants that
// follow from the claim alone are checked: for tx_count/volume the
// claim's threshold is the window in days (not the policy minimum), so
// only the one-directional implications are checkable there.
export function checkClaimsConsistent(claims) {
  const problems = [];
  for (const claim of claims) {
    const label = `claim ${claim.id}`;
    try {
      if (claim.id === 'balance_at_least' || claim.id === 'staked_at_least') {
        const value = BigInt(claim.value);
        const threshold = BigInt(claim.threshold);
        if (claim.passed !== (value >= threshold)) {
          problems.push(`${label}: passed=${claim.passed} but value ${value} vs threshold ${threshold} disagrees.`);
        }
      } else if (claim.id === 'tx_count_in_window') {
        const count = Number(claim.value);
        if (!Number.isInteger(count) || count < 0) throw new Error('unreadable count');
        if (claim.passed && count < 1) problems.push(`${label}: passed=true but zero successful txs counted.`);
      } else if (claim.id === 'volume_in_window') {
        const volume = BigInt(claim.value);
        if (claim.passed && volume <= 0n) problems.push(`${label}: passed=true but volume is zero.`);
      } else if (claim.id === 'no_failed_txs_in_window') {
        const failed = Number(claim.value);
        if (!Number.isInteger(failed) || failed < 0) throw new Error('unreadable count');
        if (claim.passed !== (failed === 0)) {
          problems.push(`${label}: passed=${claim.passed} but failed tx count is ${failed}.`);
        }
      }
      // Unknown claim ids cannot be checked from the claim alone; the
      // model still reviews them, and no problem is recorded here.
    } catch {
      problems.push(`${label}: value/threshold unreadable, cannot verify consistency.`);
    }
  }
  return { consistent: problems.length === 0, problems };
}

// The model prompt. It names the job narrowly on purpose: consistency
// of claims against metrics, nothing about the chain.
export function buildPromptMessages(claims, metrics, policyVersion) {
  const payload = JSON.stringify({ policyVersion, claims, metrics }, null, 2);
  return [
    {
      role: 'system',
      content:
        'You are the VeilProof consistency checker. You receive threshold claims and aggregate metrics about an anonymous prover. There is no wallet address, no transaction, and no identity in your input, and you must not ask for any. '
        + 'Your ONLY job is to check whether each claim is internally consistent with the metrics supplied — for example, a claim "balance_at_least passed=true" is consistent only if the balance metric is at or above its threshold, and a claim "no_failed_txs_in_window passed=true" is consistent only if the failed-tx count metric is zero. '
        + 'Do NOT verify anything about any blockchain, wallet, or transaction: chain data is verified separately by deterministic code, not by you. Do NOT invent facts, amounts, or identities. '
        + 'Reply with JSON ONLY, no other text, in exactly this shape: {"verdict": "consistent" | "inconsistent", "points": ["one short sentence per observation"]}. '
        + 'Use "inconsistent" if any claim disagrees with the metrics, or if a metric needed to check a claim is missing.',
    },
    { role: 'user', content: payload },
  ];
}

// Parse the model's reply into { verdict, points } or null when it
// cannot be understood. Tolerates ```json fences and surrounding text;
// validates the verdict and coerces points to an array of short strings.
export function parseModelOutput(content) {
  if (typeof content !== 'string') return null;
  let text = content.trim();
  if (text.length === 0) return null;
  const fenced = text.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (fenced) text = fenced[1].trim();
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    const braced = text.match(/\{[\s\S]*\}/);
    if (!braced) return null;
    try {
      parsed = JSON.parse(braced[0]);
    } catch {
      return null;
    }
  }
  if (!isObject(parsed)) return null;
  if (parsed.verdict !== 'consistent' && parsed.verdict !== 'inconsistent') return null;
  if (!Array.isArray(parsed.points)) return null;
  const points = parsed.points
    .filter((p) => typeof p === 'string')
    .map((p) => p.trim())
    .filter((p) => p.length > 0)
    .map((p) => (p.length > MAX_POINT_LEN ? p.slice(0, MAX_POINT_LEN) : p))
    .slice(0, MAX_POINTS);
  return { verdict: parsed.verdict, points };
}

// The deterministic score, reduced to exactly the fields the model
// may see: version, value (0–1000), band, and per-component points.
// Throws on malformed input, like the other sanitise functions.
export function sanitiseScore(score) {
  if (!isObject(score)) {
    throw new Error('ai-analysis: score must be an object');
  }
  if (typeof score.version !== 'string' || score.version.length === 0) {
    throw new Error('ai-analysis: score.version must be a non-empty string');
  }
  if (typeof score.value !== 'number' || !Number.isInteger(score.value) || score.value < 0 || score.value > 1000) {
    throw new Error('ai-analysis: score.value must be an integer 0-1000');
  }
  if (!['thin', 'building', 'solid', 'strong'].includes(score.band)) {
    throw new Error('ai-analysis: score.band must be thin, building, solid or strong');
  }
  if (!Array.isArray(score.components)) {
    throw new Error('ai-analysis: score.components must be an array');
  }
  const components = score.components.map((c, i) => {
    if (!isObject(c) || typeof c.id !== 'string' || c.id.length === 0) {
      throw new Error(`ai-analysis: score.components[${i}].id must be a non-empty string`);
    }
    for (const f of ['points', 'max']) {
      if (typeof c[f] !== 'number' || !Number.isInteger(c[f]) || c[f] < 0) {
        throw new Error(`ai-analysis: score.components[${i}].${f} must be a non-negative integer`);
      }
    }
    if (typeof c.measured !== 'boolean') {
      throw new Error(`ai-analysis: score.components[${i}].measured must be a boolean`);
    }
    return { id: c.id, points: c.points, max: c.max, measured: c.measured };
  });
  return { version: score.version, value: score.value, band: score.band, components };
}

// The underwriting prompt. The model judges risk from the deterministic
// facts only: the score and its components, the claims, the aggregate
// metrics. It must not treat the score as a decision by itself — the
// components and the claim pattern are the evidence.
export function buildUnderwritingPromptMessages(claims, metrics, score, policyVersion) {
  const payload = JSON.stringify({ policyVersion, claims, metrics, score }, null, 2);
  return [
    {
      role: 'system',
      content:
        'You are the VeilProof underwriting judge. You receive a deterministic credit score (0-1000, with per-component points), threshold claims, and aggregate metrics about an anonymous agent prover. There is no wallet address, no transaction, and no identity in your input, and you must not ask for any. '
        + 'Your job is a RISK JUDGMENT, not a verification: given the score, which components are strong or weak, whether the activity looks sustained or bursty, and whether any claim failed, would you lend to this agent? '
        + 'The score is a fact computed by deterministic code; treat it as the anchor, but weigh the components: a high score built only on a big balance with no activity history is weaker than a balanced score, and a low sustained-balance component means the balance may be a flash deposit. '
        + 'Do NOT verify anything about any blockchain, wallet, or transaction: chain data is verified separately by deterministic code, not by you. Do NOT invent facts, amounts, or identities. '
        + 'Amounts in your input are in yoctoNEAR unless labelled otherwise: 1 NEAR = 10^24 yoctoNEAR, so divide by 10^24 to get NEAR — a claim value of 12648773761926773600000000 yoctoNEAR is about 12.65 NEAR, not millions. '
        + 'Ground suggestedLimitNear in the measured balances in your input: it must never exceed the sustained balance — the lowest sampled balance, from the sustained_balance_at_least claim value when present, otherwise the aggregate or primary balance claim — because a limit above what the agent demonstrably held is not cautious, it is invented. A prudent limit is a fraction of what was actually held, not a multiple of it. '
        + 'Reply with JSON ONLY, no other text, in exactly this shape: {"verdict": "lend" | "lend_with_limits" | "decline", "suggestedLimitNear": <number or null>, "confidence": "low" | "medium" | "high", "points": ["one short sentence per observation"]}. '
        + 'Use "lend" only for a strong, balanced profile. Use "lend_with_limits" when the profile is decent but a component is weak or unmeasured, and set suggestedLimitNear to a cautious amount in NEAR (or null when you cannot judge an amount). Use "decline" when the score is thin, a claim failed, or the history looks gamed or too short to judge.',
    },
    { role: 'user', content: payload },
  ];
}

// Parse the underwriting model's reply into
// { verdict, suggestedLimitNear, confidence, points } or null.
// Verdict is strict; confidence coerces unknown values to 'low' and
// suggestedLimitNear coerces non-numbers to null.
export function parseUnderwritingOutput(content) {
  if (typeof content !== 'string') return null;
  let text = content.trim();
  if (text.length === 0) return null;
  const fenced = text.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (fenced) text = fenced[1].trim();
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    const braced = text.match(/\{[\s\S]*\}/);
    if (!braced) return null;
    try {
      parsed = JSON.parse(braced[0]);
    } catch {
      return null;
    }
  }
  if (!isObject(parsed)) return null;
  if (!['lend', 'lend_with_limits', 'decline'].includes(parsed.verdict)) return null;
  if (!Array.isArray(parsed.points)) return null;
  const points = parsed.points
    .filter((p) => typeof p === 'string')
    .map((p) => p.trim())
    .filter((p) => p.length > 0)
    .map((p) => (p.length > MAX_POINT_LEN ? p.slice(0, MAX_POINT_LEN) : p))
    .slice(0, MAX_POINTS);
  const suggestedLimitNear =
    typeof parsed.suggestedLimitNear === 'number' && Number.isFinite(parsed.suggestedLimitNear) && parsed.suggestedLimitNear >= 0
      ? parsed.suggestedLimitNear
      : null;
  const confidence = ['low', 'medium', 'high'].includes(parsed.confidence) ? parsed.confidence : 'low';
  return { verdict: parsed.verdict, suggestedLimitNear, confidence, points };
}

// The UNVERIFIED preflight result used when the evidence could not
// even be fetched (network, bad JSON, non-2xx). It carries the same
// shape verifyAttestationEvidence returns, so callers never have to
// handle a missing attestation object.
function unverifiedPreflight(model, error) {
  return {
    status: 'UNVERIFIED',
    method: 'near-ai-cloud-dcap',
    model,
    nonceMatched: false,
    quoteVerified: false,
    signatureVerified: false,
    measurementsChecked: false,
    expiresAt: null,
    verifiedAt: null,
    details: {},
    error,
  };
}

// Preflight attestation: GET the evidence with a fresh nonce and run
// the official verification procedure on it (src/attestation-verify.js).
// The request asks for NEAR model evidence explicitly (provider=near)
// and sends the canonical model id with x-no-aliasing, so the model
// cannot be silently substituted. Never throws: any failure (network,
// bad JSON, non-2xx, failed verification) yields an UNVERIFIED or
// FAILED preflight, and the completion may still run.
// Returns { preflight, evidence } — evidence is null when the fetch
// itself failed, so the caller can still pin a ref when it exists.
// opts.attestationNonce is a test seam: a fixed 64-hex nonce to use
// instead of a fresh random one. Production callers never pass it.
async function fetchAttestation(fetchImpl, base, model, apiKey, { policy, dcap, nonceStore, signingAlgo, attestationNonce } = {}) {
  const nonce =
    typeof attestationNonce === 'string' && /^[0-9a-fA-F]{64}$/.test(attestationNonce)
      ? attestationNonce.toLowerCase()
      : randomBytes(32).toString('hex');
  let evidence;
  try {
    const url =
      `${base}/attestation/report?model=${encodeURIComponent(model)}` +
      `&provider=near&signing_algo=${encodeURIComponent(signingAlgo)}&nonce=${nonce}`;
    const res = await fetchImpl(url, {
      method: 'GET',
      headers: { Authorization: `Bearer ${apiKey}`, 'x-no-aliasing': 'true' },
      signal: AbortSignal.timeout(ATTESTATION_TIMEOUT_MS),
    });
    if (!res.ok) {
      return { preflight: unverifiedPreflight(model, `attestation endpoint returned HTTP ${res.status}`), evidence: null };
    }
    evidence = await res.json();
  } catch (err) {
    return {
      preflight: unverifiedPreflight(model, `attestation fetch failed: ${String(err && err.message ? err.message : err).slice(0, 120)}`),
      evidence: null,
    };
  }
  const preflight = await verifyAttestationEvidence(evidence, {
    nonce,
    model,
    policy,
    dcap,
    nonceStore,
  });
  return { preflight, evidence };
}

// Shared NEAR AI call: attestation preflight, then one completion
// with the given messages, then a response-signature check. The
// request body is built ONCE and its exact bytes retained; the raw
// response bytes are retained before any JSON parsing, because the
// signature covers exactly those bytes. Returns
// { status: 'ok', content, attestation } on a non-empty completion, or
// { status, attestation, error? } with status 'not_configured' |
// 'api_error' | 'empty_output'. The caller parses `content` for its
// own job. The attestation is always attempted first; a failed
// preflight leaves the result unattested but does not abort the call.
async function callNearAi({ fetchImpl, base, model, apiKey, messages, maxTokens, policy, dcap, nonceStore, signingAlgo, attestationNonce }) {
  const { preflight, evidence } = await fetchAttestation(fetchImpl, base, model, apiKey, {
    policy,
    dcap,
    nonceStore,
    signingAlgo,
    attestationNonce,
  });
  // ref pins WHICH evidence was checked; it is a content hash, not
  // verification. It stays null when no evidence was fetched at all.
  const ref = evidence ? sha256Hex(canonicalJson(evidence)) : null;
  const requestBody = JSON.stringify({
    model,
    messages,
    temperature: 0.3,
    max_tokens: maxTokens,
  });
  const requestBytes = Buffer.from(requestBody, 'utf8');
  let content;
  let responseBytes;
  let completionBody;
  try {
    const res = await fetchImpl(`${base}/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${apiKey}`,
        'x-no-aliasing': 'true',
        // Identity encoding, so the bytes read back are the bytes the
        // gateway signed — no decompression ambiguity in the hash.
        'Accept-Encoding': 'identity',
      },
      body: requestBody,
      signal: AbortSignal.timeout(COMPLETION_TIMEOUT_MS),
    });
    if (!res.ok) {
      const attestation = { ...combineAttestation(preflight, null, { requireSignature: policy.requireSignature }), ref, verifiable: false };
      return { status: 'api_error', attestation, error: `completion endpoint returned HTTP ${res.status}` };
    }
    responseBytes = Buffer.from(await res.arrayBuffer());
    completionBody = JSON.parse(responseBytes.toString('utf8'));
    content = (completionBody.choices && completionBody.choices[0] && completionBody.choices[0].message && completionBody.choices[0].message.content) || '';
    content = String(content).trim();
  } catch (err) {
    const attestation = { ...combineAttestation(preflight, null, { requireSignature: policy.requireSignature }), ref, verifiable: false };
    return { status: 'api_error', attestation, error: String(err && err.message ? err.message : err).slice(0, 200) };
  }
  if (content.length === 0) {
    const attestation = { ...combineAttestation(preflight, null, { requireSignature: policy.requireSignature }), ref, verifiable: false };
    return { status: 'empty_output', attestation };
  }

  // Response signature: fetched only when there is a completion id to
  // bind it to AND verified preflight evidence to match its signer
  // against. Otherwise the result is UNVERIFIED by construction.
  let signature = null;
  const completionId = completionBody && typeof completionBody.id === 'string' ? completionBody.id : null;
  if (completionId !== null && preflight.status === 'VERIFIED') {
    signature = await verifyResponseSignature({
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
    });
  } else if (completionId === null) {
    signature = { status: 'UNVERIFIED', signatureVerified: false, error: 'completion id is missing, so no signature can be fetched' };
  } else {
    signature = { status: 'UNVERIFIED', signatureVerified: false, error: 'preflight evidence is not verified, so no response signature can be matched to it' };
  }
  const combined = combineAttestation(preflight, signature, { requireSignature: policy.requireSignature });
  const attestation = { ...combined, ref, verifiable: combined.status === 'VERIFIED' };
  return { status: 'ok', content, attestation };
}

// Resolve the call options shared by both jobs: key (fail closed),
// fetch, model, base URL, max tokens (floored at 800 — the model
// reasons before answering, so a smaller budget returns empty), and
// the attestation options. opts.dcap / opts.nonceStore /
// opts.attestationPolicy / opts.attestationNonce are test seams:
// without them the real @phala/dcap-qvl verifier, the process-wide
// nonce store, the env policy, and a fresh random nonce are used.
function resolveCallOpts(opts) {
  const apiKey = process.env.VEILPROOF_NEAR_AI_API_KEY;
  if (!apiKey) return { status: 'not_configured' };
  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  if (typeof fetchImpl !== 'function') {
    return { status: 'api_error', error: 'no fetch implementation available' };
  }
  const model = opts.model || process.env.VEILPROOF_NEAR_AI_MODEL || DEFAULT_MODEL;
  const base = (opts.baseUrl || process.env.VEILPROOF_NEAR_AI_API_URL || DEFAULT_BASE_URL).replace(/\/$/, '');
  const maxTokens = Math.max(MIN_MAX_TOKENS, opts.maxTokens || DEFAULT_MAX_TOKENS);
  let policy;
  try {
    policy = opts.attestationPolicy || resolveAttestationPolicy();
  } catch (err) {
    return { status: 'api_error', error: String(err && err.message ? err.message : err).slice(0, 200) };
  }
  return {
    status: 'ok',
    apiKey,
    fetchImpl,
    model,
    base,
    maxTokens,
    policy,
    dcap: opts.dcap,
    nonceStore: opts.nonceStore || defaultNonceStore,
    signingAlgo: opts.signingAlgo || DEFAULT_SIGNING_ALGO,
    attestationNonce: opts.attestationNonce,
  };
}

// Analyse evaluated claims with NEAR AI Cloud (TEE).
//   analyseClaims({ claims, metrics, policyVersion }, opts?)
// opts: { fetchImpl, model, baseUrl, maxTokens } — all optional; fetch
// defaults to the global fetch, model/baseUrl default from env
// VEILPROOF_NEAR_AI_MODEL / VEILPROOF_NEAR_AI_API_URL or the constants.
// The key is read from VEILPROOF_NEAR_AI_API_KEY at call time.
export async function analyseClaims({ claims, metrics, policyVersion }, opts = {}) {
  const cleanClaims = sanitiseClaims(claims);
  const cleanMetrics = sanitiseMetrics(metrics);
  if (typeof policyVersion !== 'string' || policyVersion.length === 0) {
    throw new Error('ai-analysis: policyVersion must be a non-empty string');
  }

  const resolved = resolveCallOpts(opts);
  if (resolved.status !== 'ok') {
    return { status: resolved.status, summary: null, ...(resolved.error ? { error: resolved.error } : {}) };
  }

  const called = await callNearAi({
    fetchImpl: resolved.fetchImpl,
    base: resolved.base,
    model: resolved.model,
    apiKey: resolved.apiKey,
    messages: buildPromptMessages(cleanClaims, cleanMetrics, policyVersion),
    maxTokens: resolved.maxTokens,
    policy: resolved.policy,
    dcap: resolved.dcap,
    nonceStore: resolved.nonceStore,
    signingAlgo: resolved.signingAlgo,
    attestationNonce: resolved.attestationNonce,
  });
  if (called.status !== 'ok') {
    return { status: called.status, summary: null, ...(called.error ? { error: called.error } : {}) };
  }

  const parsed = parseModelOutput(called.content);
  if (!parsed) {
    return { status: 'unparseable', summary: null };
  }

  // Deterministic cross-check: the model's 'consistent' must survive
  // the claim-level invariants. This can only tighten the verdict.
  let { verdict, points } = parsed;
  const check = checkClaimsConsistent(cleanClaims);
  if (verdict === 'consistent' && !check.consistent) {
    verdict = 'inconsistent';
    points = [...check.problems.map((p) => `Deterministic check: ${p}`), ...points];
  }

  return {
    status: 'ok',
    summary: {
      provider: 'near-ai',
      model: resolved.model,
      verdict,
      points,
      // The full attestation verdict: status VERIFIED / UNVERIFIED /
      // FAILED / EXPIRED plus the per-check detail. verifiable and ref
      // are kept for existing consumers: verifiable is true only when
      // the status is VERIFIED, and ref pins which evidence was
      // checked (a content hash, not verification).
      attestation: called.attestation,
    },
  };
}

// Deterministic underwriting guard (tighten only): a thin score
// cannot support a lend, however the model weighed the facts, and a
// suggested limit can never exceed what the agent demonstrably held.
// Returns the (possibly tightened) verdict object. Exported so the
// publish script applies exactly the same rule as the module.
// claims is optional: when given, the limit cap comes from the
// sustained balance claim, falling back to the aggregate balance
// claim, then the primary balance claim; without a balance claim
// there is nothing to cap against and the model's limit stands.
export function applyUnderwritingGuard(parsed, score, claims = []) {
  let { verdict, suggestedLimitNear, confidence, points } = parsed;
  if (verdict === 'lend' && score.value < 300) {
    verdict = 'decline';
    suggestedLimitNear = null;
    points = [`Deterministic guard: score ${score.value} (thin) cannot support a lend verdict.`, ...points];
  }
  if (typeof suggestedLimitNear === 'number' && Number.isFinite(suggestedLimitNear)) {
    // Priority order, not array order: the sustained balance is the
    // strongest grounding, then the aggregate, then the primary.
    const list = Array.isArray(claims) ? claims : [];
    const capClaim = ['sustained_balance_at_least', 'aggregate_balance_at_least', 'balance_at_least']
      .map((id) => list.find((c) => c?.id === id && typeof c.value === 'string' && /^\d+$/.test(c.value)))
      .find(Boolean);
    if (capClaim) {
      // Cap in NEAR, floored to 2 decimals: a limit above what the
      // agent demonstrably held is invented, however the model got there.
      const cap = Number((BigInt(capClaim.value) * 100n) / 10n ** 24n) / 100;
      if (suggestedLimitNear > cap) {
        suggestedLimitNear = cap;
        points = [`Deterministic guard: suggested limit capped at the sustained balance of ${cap} NEAR.`, ...points];
      }
    }
  }
  return { verdict, suggestedLimitNear, confidence, points };
}

// Advisory underwriting judgment with NEAR AI Cloud (TEE).
//   analyseUnderwriting({ claims, metrics, score, policyVersion }, opts?)
// The model judges risk from the deterministic score + claim facts.
// Return contract mirrors analyseClaims: { status, summary } with
// summary null on any failure mode, and the summary shape
//   { provider, model, role: 'underwriting', verdict,
//     suggestedLimitNear, confidence, points, attestation }.
// Deterministic guard (tighten only): a 'lend' verdict on a thin
// score (< 300) is overridden to 'decline'. The verdict is advisory:
// it never changes a report's validity, and a report without an
// underwriting summary is honest ("not analysed").
export async function analyseUnderwriting({ claims, metrics, score, policyVersion }, opts = {}) {
  const cleanClaims = sanitiseClaims(claims);
  const cleanMetrics = sanitiseMetrics(metrics);
  const cleanScore = sanitiseScore(score);
  if (typeof policyVersion !== 'string' || policyVersion.length === 0) {
    throw new Error('ai-analysis: policyVersion must be a non-empty string');
  }

  const resolved = resolveCallOpts(opts);
  if (resolved.status !== 'ok') {
    return { status: resolved.status, summary: null, ...(resolved.error ? { error: resolved.error } : {}) };
  }

  const called = await callNearAi({
    fetchImpl: resolved.fetchImpl,
    base: resolved.base,
    model: resolved.model,
    apiKey: resolved.apiKey,
    messages: buildUnderwritingPromptMessages(cleanClaims, cleanMetrics, cleanScore, policyVersion),
    maxTokens: resolved.maxTokens,
    policy: resolved.policy,
    dcap: resolved.dcap,
    nonceStore: resolved.nonceStore,
    signingAlgo: resolved.signingAlgo,
    attestationNonce: resolved.attestationNonce,
  });
  if (called.status !== 'ok') {
    return { status: called.status, summary: null, ...(called.error ? { error: called.error } : {}) };
  }

  const parsed = parseUnderwritingOutput(called.content);
  if (!parsed) {
    return { status: 'unparseable', summary: null };
  }

  // Deterministic guard: a thin score cannot support a lend, however
  // the model weighed the facts, and a suggested limit can never
  // exceed what the agent demonstrably held. This can only tighten
  // the verdict. The guard reads the SANITISED claims, so the cap
  // comes from the same values the model was shown.
  const { verdict, suggestedLimitNear, confidence, points } = applyUnderwritingGuard(parsed, cleanScore, cleanClaims);

  return {
    status: 'ok',
    summary: {
      provider: 'near-ai',
      model: resolved.model,
      role: 'underwriting',
      verdict,
      suggestedLimitNear,
      confidence,
      points,
      // Full attestation verdict — see analyseClaims for the shape.
      attestation: called.attestation,
    },
  };
}
