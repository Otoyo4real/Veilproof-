// VeilProof report generation — BROWSER mirror of src/report.js.
//
// Same shapes, same validation, same canonical hashing — only the hash
// primitive differs: Web Crypto (crypto.subtle, async) instead of
// node:crypto (sync), and crypto.getRandomValues instead of
// randomBytes. reportHash / evidenceHash / policyHash are therefore
// async here; buildReport itself stays sync (it computes no hash).
//
// TWO PATHS, kept in sync by the parity test in
// test/frontend-parity.test.mjs (it runs both and asserts identical
// outputs on the same fixtures):
// - Node path: src/report.js, sync, node:crypto.
// - Browser path: this file, async, Web Crypto.
// Keep the two in sync. The report carries NO hash fields; the hashes
// are computed over the report and published to the registry contract.
//
// AI summary: null means "not analysed". This module NEVER invents a
// summary: any non-null, non-object aiSummary is rejected at build time.

import { canonicalJson } from './canonical.js';
import { sha256Hex, randomHex } from './crypto.js';

export { canonicalJson };

const SHA256_HEX = /^[0-9a-f]{64}$/;
const NON_NEG_INT_STRING = /^\d+$/;

// P2 unlinkability — mirror of src/report.js. Same construction
// (SHA-256 over salt hex + address), only the hash call is async
// here because Web Crypto is async. The salt never appears in the
// public report or onchain; it travels only in the disclosure package.
export function newProverSalt() {
  return randomHex(16);
}

const SALT_HEX = /^[0-9a-f]{32}$/;

export async function saltedAddressHash(salt, address) {
  if (typeof salt !== 'string' || !SALT_HEX.test(salt)) {
    throw new Error('saltedAddressHash: salt must be 32 lowercase hex chars (16 random bytes)');
  }
  if (typeof address !== 'string' || address.length === 0) {
    throw new Error('saltedAddressHash: address must be a non-empty string');
  }
  return sha256Hex(salt + address);
}

export async function commitAddress(address, salt) {
  if (salt === undefined || salt === null) return sha256Hex(address);
  return saltedAddressHash(salt, address);
}

function requireHexHash(value, label) {
  if (typeof value !== 'string' || !SHA256_HEX.test(value)) {
    throw new Error(`report: ${label} must be a 64-char lowercase hex SHA-256, got ${JSON.stringify(value)}`);
  }
  return value;
}

function requireClaimShape(claim, index) {
  if (!claim || typeof claim !== 'object' || Array.isArray(claim)) {
    throw new Error(`report: claims[${index}] must be an object`);
  }
  if (typeof claim.id !== 'string' || claim.id.length === 0) {
    throw new Error(`report: claims[${index}].id must be a non-empty string`);
  }
  if (typeof claim.passed !== 'boolean') {
    throw new Error(`report: claims[${index}].passed must be a boolean`);
  }
  for (const field of ['value', 'threshold']) {
    const v = claim[field];
    if (typeof v !== 'string' && typeof v !== 'number') {
      throw new Error(`report: claims[${index}].${field} must be a string or number`);
    }
  }
  return claim;
}

// The hashed payload is the report minus the three hash fields. The
// report built here never contains them; stripping them here means
// hashing an annotated copy still gives the published hash.
//
// Derived fields are ALSO stripped, by design — mirror of
// src/report.js: `sampling` and the score's `riskFlags`,
// `counterpartySummary` and `disclaimer` are deterministic functions
// of the snapshots the evidence hash pins. The verifier recomputes
// them and fails the report when they differ, so their integrity is
// anchored through the evidence hash, not the report hash — and
// reports published before these fields existed keep verifying.
function hashedPayload(report) {
  const { reportHash: _rh, evidenceHash: _eh, policyHash: _ph, sampling: _s, ...payload } = report;
  if (payload.score && typeof payload.score === 'object' && !Array.isArray(payload.score)) {
    const { riskFlags: _rf, counterpartySummary: _cs, disclaimer: _d, ...hashedScore } = payload.score;
    payload.score = hashedScore;
  }
  return payload;
}

// SHA-256 hex of the canonical report payload.
export async function reportHash(report) {
  if (!report || typeof report !== 'object' || Array.isArray(report)) {
    throw new Error('reportHash: report must be an object');
  }
  return sha256Hex(canonicalJson(hashedPayload(report)));
}

// SHA-256 hex of the canonical evidence bundle. attestationRef is null
// until the NEAR AI attestation lands; a null reference hashes as null,
// which is distinct from any real reference.
export async function evidenceHash({ dataHash, attestationRef }) {
  if (typeof dataHash !== 'string' || dataHash.length === 0) {
    throw new Error('evidenceHash: dataHash must be a non-empty string');
  }
  if (attestationRef !== null && typeof attestationRef !== 'string') {
    throw new Error('evidenceHash: attestationRef must be null or a string');
  }
  return sha256Hex(canonicalJson({ attestationRef, dataHash }));
}

// SHA-256 hex of the canonical policy bundle. The verifier recomputes
// this from the policy it was given; a different policy (or version)
// gives a different hash, so the onchain record pins the exact rules
// the claims were evaluated under.
export async function policyHash(policyVersion, policy) {
  if (typeof policyVersion !== 'string' || policyVersion.length === 0) {
    throw new Error('policyHash: policyVersion must be a non-empty string');
  }
  if (!policy || typeof policy !== 'object' || Array.isArray(policy)) {
    throw new Error('policyHash: policy must be an object');
  }
  return sha256Hex(canonicalJson({ policy, policyVersion }));
}

// Build the public report.
// - proverAddressHash: SHA-256 hex of the prover's address. The address
//   itself must never appear in the report.
// - claims: the evaluated claims (from evaluateClaims). Only the ids
//   listed in disclosedFields are included; the rest are withheld.
//   disclosedFields omitted means "disclose everything evaluated".
// - aiSummary: null (not analysed yet) or a structured summary object.
//   A string is rejected: a summary must be structured, never a
//   free-form line that could be mistaken for analysis.
// - evidenceRefs: { dataHash (64-hex), attestationRef (null for now) }.
// - expiresAt: nanosecond epoch as a decimal string (same units as the
//   registry contract's expires_at and the claims engine's nowNs).
// - score: null or the deterministic score object. counterpartyLabels
//   NEVER appear in the public report (they name account ids); only
//   the label counts (counterpartySummary) do.
// - sampling: null (omitted) or the sampling record from
//   src/sampling.js. Derived from the pinned samples, excluded from
//   the report hash, recomputed and compared by the verifier.
export function buildReport({
  proverAddressHash,
  claims,
  policyVersion,
  aiSummary = null,
  evidenceRefs,
  expiresAt,
  disclosedFields,
  linkedProverHashes = [],
  score = null,
  sampling = null,
  includeExactValues = false,
}) {
  requireHexHash(proverAddressHash, 'proverAddressHash');
  if (!Array.isArray(claims)) {
    throw new Error('buildReport: claims must be an array');
  }
  claims.forEach(requireClaimShape);
  if (typeof policyVersion !== 'string' || policyVersion.length === 0) {
    throw new Error('buildReport: policyVersion must be a non-empty string');
  }
  if (aiSummary !== null && (typeof aiSummary !== 'object' || Array.isArray(aiSummary))) {
    throw new Error('buildReport: aiSummary must be null or a structured object, never a string');
  }
  if (!evidenceRefs || typeof evidenceRefs !== 'object' || Array.isArray(evidenceRefs)) {
    throw new Error('buildReport: evidenceRefs must be an object');
  }
  requireHexHash(evidenceRefs.dataHash, 'evidenceRefs.dataHash');
  if (evidenceRefs.attestationRef !== null && typeof evidenceRefs.attestationRef !== 'string') {
    throw new Error('buildReport: evidenceRefs.attestationRef must be null or a string');
  }
  if (typeof expiresAt !== 'string' || !NON_NEG_INT_STRING.test(expiresAt)) {
    throw new Error('buildReport: expiresAt must be a nanosecond epoch as a decimal string');
  }
  let disclosedIds;
  if (disclosedFields === undefined) {
    disclosedIds = claims.map((c) => c.id);
  } else {
    if (!Array.isArray(disclosedFields) || disclosedFields.some((f) => typeof f !== 'string')) {
      throw new Error('buildReport: disclosedFields must be an array of claim-id strings');
    }
    const known = new Set(claims.map((c) => c.id));
    for (const id of disclosedFields) {
      if (!known.has(id)) {
        throw new Error(`buildReport: disclosedFields names unknown claim id ${JSON.stringify(id)}`);
      }
    }
    disclosedIds = [...new Set(disclosedFields)];
  }
  const disclosedSet = new Set(disclosedIds);
  const disclosedClaims = claims.filter((c) => disclosedSet.has(c.id));

  // P3 predicate disclosure — mirror of src/report.js: the public
  // report carries thresholds and bands only. Exact claim values and
  // the exact score (plus per-component points) are stripped here, at
  // the one place a public report is built.
  const publicClaims = includeExactValues
    ? disclosedClaims
    : disclosedClaims.map((c) => ({ id: c.id, passed: c.passed, threshold: c.threshold }));
  // Public score: counterpartyLabels NEVER travel (they name account
  // ids). Risk flags, label counts and the disclaimer are public-safe
  // and travel with the score in both forms.
  const publicScoreExtras =
    score === null
      ? {}
      : {
          ...(Array.isArray(score.riskFlags) ? { riskFlags: score.riskFlags } : {}),
          ...(score.counterpartySummary && typeof score.counterpartySummary === 'object' && !Array.isArray(score.counterpartySummary)
            ? { counterpartySummary: score.counterpartySummary }
            : {}),
          ...(typeof score.disclaimer === 'string' ? { disclaimer: score.disclaimer } : {}),
        };
  // The exact form keeps the whole score except counterpartyLabels.
  const { counterpartyLabels: _cl, ...exactScore } = score === null ? {} : score;
  const publicScore =
    score === null
      ? null
      : includeExactValues
        ? { ...exactScore, ...publicScoreExtras }
        : {
            version: score.version,
            band: score.band,
            components: score.components.map((comp) => ({
              id: comp.id,
              label: comp.label,
              max: comp.max,
              measured: comp.measured,
            })),
            ...publicScoreExtras,
          };

  if (!Array.isArray(linkedProverHashes) || linkedProverHashes.some((h) => !SHA256_HEX.test(h))) {
    throw new Error('buildReport: linkedProverHashes must be an array of 64-char lowercase hex SHA-256 hashes');
  }
  if (score !== null) {
    if (typeof score !== 'object' || Array.isArray(score)) {
      throw new Error('buildReport: score must be null or a structured object');
    }
    if (typeof score.version !== 'string' || score.version.length === 0) {
      throw new Error('buildReport: score.version must be a non-empty string');
    }
    if (typeof score.value !== 'number' || !Number.isInteger(score.value) || score.value < 0 || score.value > 1000) {
      throw new Error('buildReport: score.value must be an integer 0-1000');
    }
    if (typeof score.band !== 'string' || score.band.length === 0) {
      throw new Error('buildReport: score.band must be a non-empty string');
    }
    if (!Array.isArray(score.components)) {
      throw new Error('buildReport: score.components must be an array');
    }
    if (score.riskFlags !== undefined) {
      if (
        !Array.isArray(score.riskFlags) ||
        score.riskFlags.some(
          (f) =>
            !f ||
            typeof f !== 'object' ||
            typeof f.type !== 'string' ||
            f.type.length === 0 ||
            typeof f.detail !== 'string' ||
            !['low', 'medium', 'high'].includes(f.severity),
        )
      ) {
        throw new Error('buildReport: score.riskFlags must be an array of { type, detail, severity } with severity low/medium/high');
      }
    }
    if (score.disclaimer !== undefined && typeof score.disclaimer !== 'string') {
      throw new Error('buildReport: score.disclaimer must be a string');
    }
    if (score.counterpartySummary !== undefined) {
      const s = score.counterpartySummary;
      if (
        !s ||
        typeof s !== 'object' ||
        Array.isArray(s) ||
        !['own', 'unknown', 'suspicious'].every((k) => Number.isInteger(s[k]) && s[k] >= 0)
      ) {
        throw new Error('buildReport: score.counterpartySummary must be an object with non-negative integer own/unknown/suspicious counts');
      }
    }
    if (score.counterpartyLabels !== undefined && !Array.isArray(score.counterpartyLabels)) {
      throw new Error('buildReport: score.counterpartyLabels must be an array');
    }
  }
  if (sampling !== null && sampling !== undefined) {
    if (typeof sampling !== 'object' || Array.isArray(sampling)) {
      throw new Error('buildReport: sampling must be null or a structured object');
    }
    if (!Number.isInteger(sampling.sampleCount) || sampling.sampleCount < 0) {
      throw new Error('buildReport: sampling.sampleCount must be a non-negative integer');
    }
    if (sampling.intervalBlocks !== null && (!Number.isInteger(sampling.intervalBlocks) || sampling.intervalBlocks < 0)) {
      throw new Error('buildReport: sampling.intervalBlocks must be null or a non-negative integer');
    }
    for (const f of ['oldestBlock', 'newestBlock']) {
      if (sampling[f] !== null && (!Number.isInteger(sampling[f]) || sampling[f] < 0)) {
        throw new Error(`buildReport: sampling.${f} must be null or a non-negative integer`);
      }
    }
    if (sampling.sampleTimestamps !== null && !Array.isArray(sampling.sampleTimestamps)) {
      throw new Error('buildReport: sampling.sampleTimestamps must be null or an array');
    }
    if (sampling.lowestObservedSampledBalance !== null && typeof sampling.lowestObservedSampledBalance !== 'string') {
      throw new Error('buildReport: sampling.lowestObservedSampledBalance must be null or a string');
    }
    if (typeof sampling.completeness !== 'string' || !['complete', 'partial', 'none'].includes(sampling.completeness)) {
      throw new Error('buildReport: sampling.completeness must be complete, partial or none');
    }
    if (sampling.wideIntervalWarning !== null && sampling.wideIntervalWarning !== undefined && typeof sampling.wideIntervalWarning !== 'object') {
      throw new Error('buildReport: sampling.wideIntervalWarning must be null or an object');
    }
  }

  return {
    reportId: randomHex(8),
    prover: proverAddressHash,
    linkedProvers: [...linkedProverHashes],
    createdAt: new Date().toISOString(),
    claims: publicClaims,
    policyVersion,
    aiSummary,
    evidenceRefs: { attestationRef: evidenceRefs.attestationRef, dataHash: evidenceRefs.dataHash },
    expiresAt,
    disclosed: disclosedClaims.map((c) => c.id),
    score: publicScore,
    // Present only when the prover claims sampling evidence: a
    // report without it keeps the old key set exactly.
    ...(sampling === null || sampling === undefined ? {} : { sampling }),
  };
}
