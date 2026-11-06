// VeilProof report generation — Node side (sync, node:crypto).
//
// A report is the public, shareable record of a claim. It contains
// threshold claims only ("balance >= 1 NEAR"), never the wallet address,
// never raw transactions, never exact amounts beyond the claim values
// themselves. The wallet appears only as `prover`, a SHA-256 commitment
// of the address string; the address itself lives only in the private
// disclosure package (see disclosure.js).
//
// Two hash paths exist in this codebase, by design:
// - THIS file (Node, sync, node:crypto) is the publish path: the prover
//   builds the report and computes the three hashes that go onchain.
// - public/verify.html carries an inlined copy of the same hash logic
//   built on Web Crypto (crypto.subtle, async), because the browser
//   cannot use node:crypto and cannot import ../src/ (Vercel serves
//   only public/). The parity test in test/verify-report.test.mjs runs
//   both and asserts identical verdicts. Keep the two in sync.
//
// The report itself carries NO hash fields. reportHash/evidenceHash/
// policyHash are computed over the report (minus any hash fields, if
// present) and published to the registry contract; the verifier
// recomputes them and compares with the onchain record.
//
// AI summary: the NEAR AI analysis does not exist yet, so aiSummary is
// null. A report with aiSummary null is honest ("not analysed"). This
// module NEVER invents a summary: any non-null, non-object aiSummary
// is rejected at build time.

import { createHash, randomBytes } from 'node:crypto';
import { canonicalJson } from './canonical.js';

export { canonicalJson };

const SHA256_HEX = /^[0-9a-f]{64}$/;
const NON_NEG_INT_STRING = /^\d+$/;

function sha256Hex(str) {
  return createHash('sha256').update(str, 'utf8').digest('hex');
}

// P2 unlinkability: a fresh random salt per report, so two reports
// from the same treasury get different commitments and cannot be
// matched from public data.
//
// - newProverSalt(): 16 random bytes, hex-encoded (32 chars).
// - saltedAddressHash(salt, address): SHA-256 over the UTF-8 bytes of
//   (salt hex + address). The salt NEVER appears in the public report
//   or onchain — it travels only inside the private disclosure package,
//   so a dictionary attacker cannot precompute the hash without it.
// - commitAddress(address, salt): salted when a salt is given, plain
//   sha256(address) when omitted. The plain form is the legacy
//   commitment of reports published before P2; the verifier still
//   accepts it (fallback in verify-report.js) so old reports keep
//   verifying.
export function newProverSalt() {
  return randomBytes(16).toString('hex');
}

const SALT_HEX = /^[0-9a-f]{32}$/;

export function saltedAddressHash(salt, address) {
  if (typeof salt !== 'string' || !SALT_HEX.test(salt)) {
    throw new Error('saltedAddressHash: salt must be 32 lowercase hex chars (16 random bytes)');
  }
  if (typeof address !== 'string' || address.length === 0) {
    throw new Error('saltedAddressHash: address must be a non-empty string');
  }
  return sha256Hex(salt + address);
}

export function commitAddress(address, salt) {
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
// Derived fields are ALSO stripped from the hashed payload, by
// design: `sampling` and the score's `riskFlags`,
// `counterpartySummary` and `disclaimer` are deterministic functions
// of the snapshots the evidence hash pins (the data hash covers the
// samples and txs they are computed from). The verifier recomputes
// them from the disclosure package and fails the report when they
// differ (the `sampling` and `score` checks), so their integrity is
// anchored through the evidence hash, not the report hash. Stripping
// them keeps reports published before these fields existed verifiable
// — their hash is unchanged when the fields are added — while a
// report that lies about them still fails verification. The score's
// `value`, `band` and components, and the claims, thresholds and
// expiry, stay hashed: those are the report's own assertions.
function hashedPayload(report) {
  const { reportHash: _rh, evidenceHash: _eh, policyHash: _ph, sampling: _s, ...payload } = report;
  if (payload.score && typeof payload.score === 'object' && !Array.isArray(payload.score)) {
    const { riskFlags: _rf, counterpartySummary: _cs, disclaimer: _d, ...hashedScore } = payload.score;
    payload.score = hashedScore;
  }
  return payload;
}

// SHA-256 hex of the canonical report payload.
export function reportHash(report) {
  if (!report || typeof report !== 'object' || Array.isArray(report)) {
    throw new Error('reportHash: report must be an object');
  }
  return sha256Hex(canonicalJson(hashedPayload(report)));
}

// SHA-256 hex of the canonical evidence bundle. attestationRef is null
// until the NEAR AI attestation lands; a null reference hashes as null,
// which is distinct from any real reference.
export function evidenceHash({ dataHash, attestationRef }) {
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
export function policyHash(policyVersion, policy) {
  if (typeof policyVersion !== 'string' || policyVersion.length === 0) {
    throw new Error('policyHash: policyVersion must be a non-empty string');
  }
  if (!policy || typeof policy !== 'object' || Array.isArray(policy)) {
    throw new Error('policyHash: policy must be an object');
  }
  return sha256Hex(canonicalJson({ policy, policyVersion }));
}

// Build the public report.
// - proverAddressHash: SHA-256 hex commitment of the prover's address.
//   Since P2 this is normally the SALTED commitment
//   (saltedAddressHash(salt, address), salt fresh per report, salt
//   carried only in the disclosure package) — two reports from the
//   same treasury then have different commitments and cannot be
//   matched from public data. The plain sha256(address) form is the
//   legacy commitment of pre-P2 reports; the verifier still accepts it.
// - claims: the evaluated claims (from evaluateClaims). Only the ids
//   listed in disclosedFields are included; the rest are withheld.
//   disclosedFields omitted means "disclose everything evaluated".
// - aiSummary: null (not analysed yet) or a structured summary object.
//   A string is rejected: a summary must be structured, never a
//   free-form line that could be mistaken for analysis.
// - evidenceRefs: { dataHash (64-hex), attestationRef (null for now) }.
// - expiresAt: nanosecond epoch as a decimal string (same units as the
//   registry contract's expires_at and the claims engine's nowNs).
// - linkedProverHashes: SHA-256 hex commitments of any additional
//   wallets the prover linked to this report (multi-wallet aggregate
//   claims). Empty (the default) means a single-wallet report. Each
//   linked wallet's ownership is proven by a linking transfer to the
//   primary wallet (see verify-report.js link_proofs); the addresses
//   themselves live only in the disclosure package.
// - score: null (not scored) or the deterministic score object from
//   src/score.js ({ version, value, band, components, riskFlags,
//   counterpartyLabels, counterpartySummary, disclaimer }). A report
//   without a score is honest ("not scored"); the verifier recomputes
//   the score when one is present and fails the report when it differs.
//   counterpartyLabels NEVER appear in the public report (they name
//   account ids); only the label counts (counterpartySummary) do.
// - sampling: null (omitted — no sampling evidence claimed) or the
//   sampling record from src/sampling.js ({ intervalBlocks,
//   sampleCount, oldestBlock, newestBlock, sampleTimestamps,
//   lowestObservedSampledBalance, completeness, wideIntervalWarning,
//   ... }). It is a derived summary of the pinned samples, so it is
//   excluded from the report hash (see hashedPayload) and the
//   verifier recomputes it from the disclosure snapshots. Note the
//   deliberate P3 exception: the record carries the lowest OBSERVED
//   sampled balance as an exact value — the sampling evidence is only
//   meaningful with its observed minimum, and the sustained claim's
//   threshold is already public. Exact claim values and score points
//   stay stripped; this one exact value is the sampling evidence
//   itself, cross-checked by the verifier against the pinned samples.
// - includeExactValues (default false, P3): when false, the public
//   report carries PREDICATES only — claims keep { id, passed,
//   threshold } and the score keeps { version, band, components
//   without points }. The exact values stay in the private disclosure
//   package (the verifier recomputes them from the snapshots). When
//   true, the exact values are kept — legacy format only, for tests
//   and for verifying old reports. Never set it for a new publish.
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

  // P3 predicate disclosure: the public report carries thresholds and
  // bands only. Exact claim values and the exact score (plus per-
  // component points) are stripped here, at the one place a public
  // report is built, so no caller can publish them by accident. The
  // verifier recomputes the exact values from the disclosure
  // snapshots and checks them against these predicates.
  const publicClaims = includeExactValues
    ? disclosedClaims
    : disclosedClaims.map((c) => ({ id: c.id, passed: c.passed, threshold: c.threshold }));
  // Public score: counterpartyLabels NEVER travel (they name account
  // ids — see disclosure.js). Risk flags, label counts and the
  // disclaimer are public-safe and travel with the score in both
  // forms; the verifier recomputes them from the snapshots.
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
  // The exact form keeps the whole score except counterpartyLabels:
  // account ids never go in a public report, even a legacy one.
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
    reportId: randomBytes(8).toString('hex'),
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
