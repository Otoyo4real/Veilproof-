// VeilProof NEAR AI analysis — TEE-attested consistency check of claims.
//
// The model reads ONLY claim-level data: claim ids, passed/value/threshold
// and aggregate metrics (counts, volumes, window days). It never sees the
// wallet address, never sees a transaction hash, never sees the raw
// snapshot. Sanitisation is an allowlist, not a denylist: only the fields
// named in sanitiseClaims / sanitiseMetrics ever enter a request payload,
// so a caller cannot leak the address by stuffing it into the metrics.
//
// The model does NOT verify anything about the chain. Its only job is
// internal consistency: does each claim agree with the metrics it was
// evaluated from? Chain truth is verified deterministically by
// src/verify-report.js (re-fetch + re-run). The model's verdict is also
// cross-checked here by checkClaimsConsistent: a 'consistent' verdict
// from the model is overridden to 'inconsistent' when a claim
// contradicts itself (e.g. passed=true while value < threshold). The
// check can only make a verdict stricter, never looser.
//
// Attestation follows the Genesis worker pattern (see
// ~/workspace/genesis/src/worker-llm.js, read-only reference): a
// preflight GET of /v1/attestation/report with a fresh random nonce,
// trusted ONLY when the gateway or model report echoes that nonce.
// The full evidence (~300 KB) is never stored in the summary; the
// summary carries only attestation.ref, the SHA-256 of the canonical
// evidence JSON, which pins the evidence content. A nonce mismatch or a
// failed preflight does NOT abort the analysis — the completion still
// runs, but the summary is labelled unattested (verifiable false,
// ref null). Never attested on untrusted evidence.
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
//     points: string[], attestation: { verifiable, nonceMatched, ref } }
// The summary's attestation.ref (or null) is the attestationRef to pass
// to evidenceHash / buildReport.
//
// Model gotcha (from the Genesis worker): the default model reasons
// before answering, so a small max_tokens is spent entirely on
// reasoning and returns empty content. maxTokens is therefore floored
// at 800 — a caller asking for less gets 800, silently and safely.

import { createHash, randomBytes } from 'node:crypto';
import { canonicalJson } from './canonical.js';

export const DEFAULT_MODEL = 'z-ai/glm-5.3-flash';
export const DEFAULT_BASE_URL = 'https://cloud-api.near.ai/v1';

const MIN_MAX_TOKENS = 800;
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

// Preflight attestation: GET the evidence with a fresh nonce and trust
// it only when the gateway or the first model report echoes that nonce.
// Never throws: any failure (network, bad JSON, non-2xx, mismatch)
// yields an unattested result, and the completion may still run.
async function fetchAttestation(fetchImpl, base, model, apiKey) {
  const unattested = (detail) => ({
    verifiable: false,
    nonceMatched: false,
    ref: null,
    detail,
  });
  const nonce = randomBytes(32).toString('hex');
  let evidence;
  try {
    const url =
      `${base}/attestation/report?model=${encodeURIComponent(model)}` +
      `&signing_algo=ecdsa&nonce=${nonce}`;
    const res = await fetchImpl(url, {
      method: 'GET',
      headers: { Authorization: `Bearer ${apiKey}`, 'x-no-aliasing': 'true' },
      signal: AbortSignal.timeout(ATTESTATION_TIMEOUT_MS),
    });
    if (!res.ok) return unattested(`attestation endpoint returned HTTP ${res.status}`);
    evidence = await res.json();
  } catch (err) {
    return unattested(`attestation fetch failed: ${String(err && err.message ? err.message : err).slice(0, 120)}`);
  }
  if (!isObject(evidence)) return unattested('attestation evidence was not a JSON object');
  const gatewayNonce = evidence.gateway_attestation && evidence.gateway_attestation.request_nonce;
  const modelNonce =
    evidence.model_attestations && evidence.model_attestations[0] && evidence.model_attestations[0].request_nonce;
  if (gatewayNonce !== nonce && modelNonce !== nonce) {
    return unattested('attestation nonce mismatch: evidence cannot be tied to this request');
  }
  return {
    verifiable: true,
    nonceMatched: true,
    ref: sha256Hex(canonicalJson(evidence)),
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

  const apiKey = process.env.VEILPROOF_NEAR_AI_API_KEY;
  if (!apiKey) {
    return { status: 'not_configured', summary: null };
  }

  const fetchImpl = opts.fetchImpl || globalThis.fetch;
  if (typeof fetchImpl !== 'function') {
    return { status: 'api_error', summary: null, error: 'no fetch implementation available' };
  }
  const model = opts.model || process.env.VEILPROOF_NEAR_AI_MODEL || DEFAULT_MODEL;
  const base = (opts.baseUrl || process.env.VEILPROOF_NEAR_AI_API_URL || DEFAULT_BASE_URL).replace(/\/$/, '');
  const maxTokens = Math.max(MIN_MAX_TOKENS, opts.maxTokens || MIN_MAX_TOKENS);

  // Attestation preflight first (a report fetched after the completion
  // cannot replace preflight evidence). A failed preflight leaves the
  // summary unattested but does not abort the analysis.
  const attestation = await fetchAttestation(fetchImpl, base, model, apiKey);

  let content;
  try {
    const res = await fetchImpl(`${base}/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${apiKey}`,
        'x-no-aliasing': 'true',
      },
      body: JSON.stringify({
        model,
        messages: buildPromptMessages(cleanClaims, cleanMetrics, policyVersion),
        temperature: 0.3,
        max_tokens: maxTokens,
      }),
      signal: AbortSignal.timeout(COMPLETION_TIMEOUT_MS),
    });
    if (!res.ok) {
      return { status: 'api_error', summary: null, error: `completion endpoint returned HTTP ${res.status}` };
    }
    const body = await res.json();
    content = (body.choices && body.choices[0] && body.choices[0].message && body.choices[0].message.content) || '';
    content = String(content).trim();
  } catch (err) {
    return { status: 'api_error', summary: null, error: String(err && err.message ? err.message : err).slice(0, 200) };
  }
  if (content.length === 0) {
    return { status: 'empty_output', summary: null };
  }

  const parsed = parseModelOutput(content);
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
      model,
      verdict,
      points,
      attestation: {
        verifiable: attestation.verifiable,
        nonceMatched: attestation.nonceMatched,
        ref: attestation.ref,
      },
    },
  };
}
