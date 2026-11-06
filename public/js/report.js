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
function hashedPayload(report) {
  const { reportHash: _rh, evidenceHash: _eh, policyHash: _ph, ...payload } = report;
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
export function buildReport({
  proverAddressHash,
  claims,
  policyVersion,
  aiSummary = null,
  evidenceRefs,
  expiresAt,
  disclosedFields,
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

  return {
    reportId: randomHex(8),
    prover: proverAddressHash,
    createdAt: new Date().toISOString(),
    claims: disclosedClaims,
    policyVersion,
    aiSummary,
    evidenceRefs: { attestationRef: evidenceRefs.attestationRef, dataHash: evidenceRefs.dataHash },
    expiresAt,
    disclosed: disclosedClaims.map((c) => c.id),
  };
}
