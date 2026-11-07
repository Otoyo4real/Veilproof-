// VeilProof report verification — Node side (sync, node:crypto).
//
// Pure function: everything it needs arrives as parameters. The caller
// fetches the onchain record from the registry (get_claim +
// is_claim_valid) and passes it in, so this stays testable with no
// network and no keys.
//
// Two hash paths exist in this codebase, by design:
// - THIS file (Node, sync, node:crypto) is the server/CLI path.
// - public/verify.html carries an inlined copy built on Web Crypto
//   (crypto.subtle, async), because the browser cannot use node:crypto
//   and cannot import ../src/ (Vercel serves only public/). The parity
//   test in test/verify-report.test.mjs runs the page's copy in a VM
//   and asserts identical verdicts. Keep the two in sync.
//
// What each check proves (and what it does not):
// - prover_binding: the disclosure package belongs to this report
//   (the address hashes to the report's prover commitment).
// - report_hash / evidence_hash / policy_hash: the report, the
//   evidence bundle and the policy are exactly what was published
//   onchain. A single changed claim, hash or rule fails these.
// - data_hash: the snapshot(s) the verifier was given reproduce
//   the data hash the report commits to. Single-wallet reports
//   without samples use the original hash; multi-wallet reports or
//   reports with balance samples use the multi-wallet hash, which
//   covers every wallet's state, txs and samples.
// - sampling: the report's sampling record (interval, count, heights,
//   timestamps, lowest observed sampled balance, completeness, wide-
//   interval warning) matches the recomputation from the disclosed
//   snapshots. The record is a derived summary of the pinned samples
//   and is NOT part of the report hash (see report.js), so this check
//   is what stops a report from misstating it. A report that claims
//   no sampling evidence passes vacuously — the check only binds what
//   the report claims — and a wide interval is a WARNING in the
//   detail, not a failure: the evidence is thin, not false.
// - claims: re-running the claims engine on the disclosed snapshot(s)
//   under the disclosed policy reproduces the report's claims
//   (same ids, same passed, same values). Claims the prover chose
//   NOT to disclose are simply absent from the report; the re-run may
//   contain more claims than the report, and that is fine.
// - score: when the report carries a deterministic score, recomputing
//   it from the disclosed snapshots under the disclosed policy
//   reproduces it exactly (same value, band and components). A report
//   without a score passes vacuously ("not scored"). When the report
//   carries risk flags, a counterparty summary or a disclaimer, those
//   must match the recomputation too; reports published before they
//   existed carry none of them and are not penalised for it. Risk
//   flags are advisory: a report with flags still verifies when the
//   recomputation matches — the flags are surfaced in the detail, not
//   treated as a failure.
// - link_proofs: every linked wallet proves ownership, by one of two
//   methods — a linking transfer to the primary address, present
//   among the disclosed txs, OR a NEP-413 signature over the link
//   statement for this exact pairing. A signature link additionally
//   requires its public key to be bound to the linked account: the
//   caller verifies that binding against the chain's access key list
//   (RPC) and passes it as linkKeyBindings { address: publicKey }.
//   This function stays pure (no network): without a binding for a
//   signature-linked wallet, the check fails rather than trusting
//   the key in the disclosure package. A report with no linked
//   wallets passes vacuously.
// - validity: the report is unexpired and the registry still reports
//   the claim valid (not revoked, not expired, exists).
//
// What verification does NOT prove: that the chain data is "real" in
// some offchain sense — it is real because it is onchain and the
// verifier re-reads it. It does not prove anything about data that
// never touched the chain. And a null aiSummary means "not analysed":
// verification never requires an AI summary and never invents one.
// The AI underwriting verdict is advisory only: it is never a
// validity condition, and a report's validity never depends on it.
//
// Failure policy: a failed check is recorded, never thrown. Only
// malformed input throws — a missing/non-object report, onchain
// record, disclosure package or policy, a missing disclosure
// snapshot, or an unusable nowNs. Everything about the CONTENT of
// those objects is a failed check, not an exception.

import { createHash } from 'node:crypto';
import { evaluateClaims, unionTxs } from './claims-engine.js';
import { dataHashForSnapshots } from './onchain.js';
import { computeScore } from './score.js';
import { describeSampling } from './sampling.js';
import { canonicalJson } from './canonical.js';
import { reportHash, evidenceHash, policyHash, saltedAddressHash } from './report.js';
import { buildLinkMessage, verifyLinkSignature } from './nep413.js';

const SHA256_HEX = /^[0-9a-f]{64}$/;

function sha256Hex(str) {
  return createHash('sha256').update(str, 'utf8').digest('hex');
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function shortHash(hash) {
  return typeof hash === 'string' ? hash : '(missing)';
}

// --- Verification model: five separate statuses ---
//
// verifyReport returns the ten checks as before, plus one status
// field per question a verifier actually asks, each with its own
// state. The overall `valid` boolean stays as a clearly labelled
// summary (all ten required checks pass), but the fields are never
// combined into a stronger claim than the evidence supports:
// - source_status: VERIFIED | UNVERIFIED | FAILED. The disclosed
//   snapshot reproduces the data hash committed onchain. It does NOT
//   mean the verifier refetched the account state from the chain:
//   the snapshot comes from the disclosure package, and the check
//   ties it to the onchain hash.
// - computation_status: VERIFIED | UNVERIFIED | FAILED. The claims,
//   the deterministic score, the sampling record and the wallet link
//   proofs were rerun from the disclosure snapshot and reproduce the
//   report.
// - attestation_status: VERIFIED | UNVERIFIED | FAILED | EXPIRED.
//   The TEE attestation behind the AI summary. VERIFIED only when
//   the nonce, quote, signature and measurements were all checked
//   (see deriveAttestationStatus). A report whose AI summary only
//   records a nonce match is UNVERIFIED, never VERIFIED.
// - report_integrity_status: VERIFIED | UNVERIFIED | FAILED |
//   REVOKED | EXPIRED. The report matches its published record,
//   is unexpired, and the registry still reports the claim valid.
// - privacy_status: PRIVATE | PARTIALLY_DISCLOSED | PUBLIC. What
//   the PUBLIC report discloses, not what the verifier sees: the
//   verifier holds the disclosure package, so the verifier sees the
//   address and the exact values. A salted predicate report is
//   PRIVATE; a legacy report with exact values or an unsalted
//   commitment is PARTIALLY_DISCLOSED.
//
// Sampling and score limits are descriptive derivations from the
// disclosure, not new evidence. The sampling record is
// describeSampling (src/sampling.js): the same record the report
// carries and the `sampling` check verifies — interval, count,
// heights, timestamps, lowest observed sampled balance,
// completeness, wide-interval warning. Score limits read the
// recomputed score: its manipulation risk flags (circular flows,
// shared funders, concentration, repeated transfers) plus
// component-derived flags for unmeasured or thin components, and
// its counterparty labels (own / unknown / suspicious). When the
// parallel attestation work lands, its attestation input replaces
// the derived attestation status; until then the panels render the
// derived values honestly and say what was not checked.

function checkPassed(checks, name) {
  const found = checks.find((c) => c.check === name);
  return !!found && found.passed;
}

// --- Score limits: consumed from the recomputed score ---
//
// computeScore (score.js) already returns riskFlags,
// counterpartyLabels, counterpartySummary and disclaimer, produced by
// manipulation.js. The derivation section below passes them through
// from the recomputed score, with per-component points stripped (the
// public report carries a band only). Nothing here invents a risk
// flag or a counterparty label.

function deriveAttestationStatus(attestationInput, report, nowNs) {
  // The attestation result interface the parallel attestation work
  // produces: { status, method, model, nonceMatched, quoteVerified,
  // signatureVerified, measurementsChecked, expiresAt, details,
  // error? }. When that input is supplied it is used, with one
  // guard: VERIFIED is accepted only when the nonce, quote,
  // signature and measurements were all confirmed. A VERIFIED claim
  // with a failed check becomes FAILED; with a check simply not
  // confirmed it becomes UNVERIFIED. Without the input, the status
  // is derived from the report AI summary alone, and the most it can
  // ever reach is UNVERIFIED: the summary records a nonce match at
  // analysis time, but this verifier did not recheck the quote,
  // signature or measurements, and the full evidence is not in the
  // report, only its hash.
  const tri = (v) => (v === true ? true : v === false ? false : null);
  const build = (patch) => ({
    status: 'UNVERIFIED',
    method: null,
    model: null,
    nonceMatched: null,
    quoteVerified: null,
    signatureVerified: null,
    measurementsChecked: null,
    expiresAt: null,
    detail: '',
    ...patch,
  });
  if (isObject(attestationInput)) {
    const method = typeof attestationInput.method === 'string' ? attestationInput.method : null;
    const model = typeof attestationInput.model === 'string' ? attestationInput.model : null;
    const nonceMatched = tri(attestationInput.nonceMatched);
    const quoteVerified = tri(attestationInput.quoteVerified);
    const signatureVerified = tri(attestationInput.signatureVerified);
    const measurementsChecked = tri(attestationInput.measurementsChecked);
    const expiresAt = typeof attestationInput.expiresAt === 'string' ? attestationInput.expiresAt : null;
    const details = typeof attestationInput.details === 'string' ? attestationInput.details : null;
    const error = typeof attestationInput.error === 'string' ? attestationInput.error : null;
    const common = { method, model, nonceMatched, quoteVerified, signatureVerified, measurementsChecked, expiresAt };
    if (attestationInput.status === 'VERIFIED') {
      const allTrue =
        nonceMatched === true && quoteVerified === true && signatureVerified === true && measurementsChecked === true;
      const anyFalse =
        nonceMatched === false || quoteVerified === false || signatureVerified === false || measurementsChecked === false;
      if (allTrue) {
        // A VERIFIED result whose evidence is past its validity
        // period is EXPIRED, not VERIFIED (same rule as
        // attestationStatusAt in attestation-verify.js).
        let expired = false;
        try {
          if (typeof expiresAt === 'string' && expiresAt) {
            expired = Date.parse(expiresAt) <= Number(BigInt(nowNs) / 1000000n);
          }
        } catch {
          expired = false;
        }
        if (expired) {
          return build({
            ...common,
            status: 'EXPIRED',
            detail: details || 'The attestation evidence is past its validity period.',
          });
        }
        return build({
          ...common,
          status: 'VERIFIED',
          detail: details || 'The TEE attestation was cryptographically verified: nonce, quote, signature and measurements all checked.',
        });
      }
      if (anyFalse) {
        return build({
          ...common,
          status: 'FAILED',
          detail:
            details ||
            error ||
            'The attestation was reported verified but one of the required checks failed, so it is not treated as verified.',
        });
      }
      return build({
        ...common,
        status: 'UNVERIFIED',
        detail:
          details ||
          'The attestation was reported verified but not every required check was confirmed, so it is not treated as verified.',
      });
    }
    if (attestationInput.status === 'FAILED') {
      return build({ ...common, status: 'FAILED', detail: details || error || 'The attestation check failed.' });
    }
    if (attestationInput.status === 'EXPIRED') {
      return build({ ...common, status: 'EXPIRED', detail: details || 'The attestation expired.' });
    }
    return build({ ...common, status: 'UNVERIFIED', detail: details || 'The attestation was not verified.' });
  }
  const ai = report.aiSummary;
  if (!isObject(ai)) {
    return build({
      detail: 'No AI summary is attached to this report, so there is no attestation to check. A report does not need an AI summary to verify.',
    });
  }
  const model = typeof ai.model === 'string' ? ai.model : null;
  const att = ai.attestation;
  if (!isObject(att)) {
    return build({
      method: 'NEAR AI attestation preflight, nonce echo',
      model,
      detail: 'An AI analysis is attached but it carries no attestation record, so the attestation was not checked.',
    });
  }
  const nonceMatched = tri(att.nonceMatched);
  // The attestation record carries its own status (post-remediation):
  // respect it. A record that says UNVERIFIED was not verified, not
  // failed — the nonce echo is relabelled UNVERIFIED, and only a
  // record that says FAILED (nonce mismatch, bad quote or signature)
  // is a failure. VERIFIED is downgraded to UNVERIFIED here because
  // this verifier did not recheck the quote, signature or
  // measurements from the report alone (only the ref hash is in the
  // report). Legacy records have no status field; for those, the old
  // nonce-echo stamp (verifiable true with a matched nonce) is also
  // UNVERIFIED. (verifiable is true only when the record status is
  // VERIFIED, so it can no longer be the test for the nonce echo.)
  const recordStatus = typeof att.status === 'string' ? att.status : null;
  if (recordStatus === 'FAILED') {
    return build({
      status: 'FAILED',
      method: 'NEAR AI attestation preflight, nonce echo',
      model,
      nonceMatched,
      detail:
        'The attestation did not verify when the analysis ran, so the AI analysis is unattested. The report itself can still verify, only the AI opinion lacks attestation.',
    });
  }
  if (recordStatus === 'EXPIRED') {
    return build({
      status: 'EXPIRED',
      method: 'NEAR AI attestation preflight, nonce echo',
      model,
      nonceMatched,
      detail: 'The attestation evidence is past its validity period.',
    });
  }
  if (
    recordStatus === 'VERIFIED' ||
    recordStatus === 'UNVERIFIED' ||
    (att.verifiable === true && nonceMatched === true)
  ) {
    return build({
      method: 'NEAR AI attestation preflight, nonce echo',
      model,
      nonceMatched: true,
      detail:
        'The analysis recorded that its nonce matched when it ran, but this verifier did not recheck the TEE quote, signature or measurements. The full attestation evidence is not in the report, only its hash, so the quote cannot be rechecked from the report alone.',
    });
  }
  return build({
    status: 'FAILED',
    method: 'NEAR AI attestation preflight, nonce echo',
    model,
    nonceMatched,
    detail:
      'The attestation did not verify when the analysis ran, so the AI analysis is unattested. The report itself can still verify, only the AI opinion lacks attestation.',
  });
}

// One summary headline for the page banner, derived from the five
// statuses, never from the valid boolean alone. Priority: a revoked,
// expired or tampered report is bad news first; then a failed source
// or computation; then an attestation that failed or expired, then
// one that was simply not verified. The notes name every limitation
// so the headline never hides one.
export function summariseVerification(result) {
  const field = (name) =>
    result && result[name] && typeof result[name] === 'object' ? result[name] : {};
  const integrity = field('report_integrity_status');
  const source = field('source_status');
  const computation = field('computation_status');
  const attestation = field('attestation_status');
  const privacy = field('privacy_status');
  const notes = [];
  const failed = [];
  let headline;
  let tone;
  if (integrity.status === 'REVOKED') {
    headline = 'Revoked: this report was withdrawn from the registry.';
    tone = 'bad';
    failed.push('report_integrity_status');
  } else if (integrity.status === 'EXPIRED') {
    headline = 'Expired: this report is past its expiry date.';
    tone = 'bad';
    failed.push('report_integrity_status');
  } else if (integrity.status === 'FAILED') {
    headline = 'Does not verify: the report does not match its published record.';
    tone = 'bad';
    failed.push('report_integrity_status');
  } else if (source.status === 'FAILED') {
    headline = 'Does not verify: the disclosed data does not match the published data hash.';
    tone = 'bad';
    failed.push('source_status');
  } else if (computation.status === 'FAILED') {
    headline = 'Does not verify: the claims, score, sampling or link proofs did not reproduce from the disclosure.';
    tone = 'bad';
    failed.push('computation_status');
  } else if (result.valid === false) {
    headline = 'Does not verify: one or more checks failed, see the check list below.';
    tone = 'bad';
  } else if (attestation.status === 'FAILED') {
    headline = 'Checks pass, but the AI attestation failed.';
    tone = 'warn';
    failed.push('attestation_status');
  } else if (attestation.status === 'EXPIRED') {
    headline = 'Checks pass, but the AI attestation expired.';
    tone = 'warn';
    failed.push('attestation_status');
  } else if (attestation.status === 'UNVERIFIED') {
    headline = 'Checks pass, AI attestation not verified.';
    tone = 'warn';
  } else if (source.status === 'UNVERIFIED' || computation.status === 'UNVERIFIED' || integrity.status === 'UNVERIFIED') {
    headline = 'Checks pass, but one status could not be confirmed.';
    tone = 'warn';
  } else {
    headline = 'Verified: every check passed.';
    tone = 'ok';
  }
  if (source.status === 'FAILED') notes.push(`Source data: ${source.detail || 'failed.'}`);
  if (computation.status === 'FAILED') notes.push(`Computation: ${computation.detail || 'failed.'}`);
  if (integrity.status === 'FAILED' || integrity.status === 'REVOKED' || integrity.status === 'EXPIRED') {
    notes.push(`Report integrity: ${integrity.detail || 'failed.'}`);
  }
  if (integrity.status === 'UNVERIFIED') {
    notes.push('Report integrity: the registry did not confirm the claim, see the integrity panel.');
  }
  if (attestation.status === 'FAILED') notes.push('Attestation: the AI attestation failed, see the attestation panel.');
  if (attestation.status === 'EXPIRED') notes.push('Attestation: the AI attestation expired, see the attestation panel.');
  if (attestation.status === 'UNVERIFIED') {
    notes.push('Attestation: not verified, see the attestation panel for what was and was not checked.');
  }
  if (privacy.status === 'PARTIALLY_DISCLOSED') {
    notes.push('Privacy: the public report discloses more than a predicate report, see the privacy panel.');
  }
  if (privacy.status === 'PUBLIC') notes.push('Privacy: the public report names the wallet address, see the privacy panel.');
  if (result.sampling && result.sampling.wideIntervalWarning) {
    notes.push('Sampling: the sampling record carries a wide interval warning, see the sampling panel.');
  }
  if (result.score && Array.isArray(result.score.riskFlags) && result.score.riskFlags.length > 0) {
    notes.push('Credit score: this report carries risk flags, see the score panel.');
  }
  return { headline, tone, notes, failed };
}

export function verifyReport({ report, onchainRecord, disclosurePackage, policy, nowNs, linkKeyBindings, attestation }) {
  if (!isObject(report)) throw new Error('verifyReport: report must be an object');
  if (!isObject(onchainRecord)) throw new Error('verifyReport: onchainRecord must be an object');
  if (!isObject(disclosurePackage)) throw new Error('verifyReport: disclosurePackage must be an object');
  if (!isObject(disclosurePackage.snapshot)) {
    throw new Error('verifyReport: disclosurePackage.snapshot must be an object');
  }
  if (!isObject(policy)) throw new Error('verifyReport: policy must be an object');
  let now;
  try {
    now = BigInt(nowNs);
  } catch {
    throw new Error('verifyReport: nowNs must be a nanosecond epoch (string, number or bigint)');
  }

  const checks = [];
  const check = (name, passed, detail) => checks.push({ check: name, passed, detail });

  // All disclosed snapshots: the primary one plus any linked wallets'.
  const snapshots = [disclosurePackage.snapshot];
  const linked = Array.isArray(disclosurePackage.linked) ? disclosurePackage.linked : [];
  for (const entry of linked) {
    if (entry && typeof entry === 'object' && entry.snapshot) snapshots.push(entry.snapshot);
  }
  const bundle = { wallets: snapshots };

  // 0. The disclosure package belongs to this report. With a salt
  // (P2) the binding is the salted commitment; without one it is the
  // legacy plain sha256(address) of pre-P2 reports. The salt travels
  // only in the disclosure package, so a salted report stays
  // unlinkable from public data.
  const addressMatchesCommitment = (address, salt, commitment) => {
    if (salt === undefined || salt === null) return sha256Hex(address) === commitment;
    if (typeof salt !== 'string' || !/^[0-9a-f]{32}$/.test(salt)) return false;
    return saltedAddressHash(salt, address) === commitment;
  };
  if (typeof disclosurePackage.address !== 'string' || disclosurePackage.address.length === 0) {
    check('prover_binding', false, 'Disclosure package has no address.');
  } else if (typeof report.prover !== 'string' || report.prover.length === 0) {
    check('prover_binding', false, 'Report has no prover commitment.');
  } else if (!addressMatchesCommitment(disclosurePackage.address, disclosurePackage.salt, report.prover)) {
    check('prover_binding', false, 'Disclosure address does not hash to the report prover commitment.');
  } else if (linked.length > 0) {
    const linkedProvers = Array.isArray(report.linkedProvers) ? report.linkedProvers : [];
    const bad = linked.findIndex(
      (entry, i) =>
        typeof entry?.address !== 'string' ||
        entry.address.length === 0 ||
        !addressMatchesCommitment(entry.address, entry.salt, linkedProvers[i]),
    );
    if (bad >= 0) {
      check('prover_binding', false, `Linked wallet ${bad} does not hash to the report linked-prover commitment.`);
    } else {
      check('prover_binding', true, 'Disclosure addresses hash to the report prover commitments.');
    }
  } else {
    check('prover_binding', true, 'Disclosure address hashes to the report prover commitment.');
  }

  // a. The report is exactly what was published.
  try {
    const computed = reportHash(report);
    if (onchainRecord.report_hash === computed) {
      check('report_hash', true, 'Report hash matches the onchain record.');
    } else {
      check('report_hash', false, `Report hash ${computed} does not match onchain ${shortHash(onchainRecord.report_hash)}.`);
    }
  } catch (err) {
    check('report_hash', false, `Could not compute report hash: ${err.message}`);
  }

  // b. The evidence bundle is exactly what was published.
  try {
    const computed = evidenceHash(report.evidenceRefs);
    if (onchainRecord.evidence_hash === computed) {
      check('evidence_hash', true, 'Evidence hash matches the onchain record.');
    } else {
      check('evidence_hash', false, `Evidence hash ${computed} does not match onchain ${shortHash(onchainRecord.evidence_hash)}.`);
    }
  } catch (err) {
    check('evidence_hash', false, `Could not compute evidence hash: ${err.message}`);
  }

  // c. The policy is exactly what was published.
  try {
    const computed = policyHash(report.policyVersion, policy);
    if (onchainRecord.policy_hash === computed) {
      check('policy_hash', true, 'Policy hash matches the onchain record.');
    } else {
      check('policy_hash', false, `Policy hash ${computed} does not match onchain ${shortHash(onchainRecord.policy_hash)}.`);
    }
  } catch (err) {
    check('policy_hash', false, `Could not compute policy hash: ${err.message}`);
  }

  // d. The disclosed snapshot(s) reproduce the committed data hash.
  try {
    const computed = dataHashForSnapshots(snapshots);
    const ref = report.evidenceRefs?.dataHash;
    if (computed === ref) {
      check('data_hash', true, 'Recomputed data hash matches the report evidence reference.');
    } else {
      check('data_hash', false, `Recomputed data hash ${computed} does not match report evidence reference ${shortHash(ref)}.`);
    }
  } catch (err) {
    check('data_hash', false, `Could not recompute data hash: ${err.message}`);
  }

  // e. The report's sampling record matches the recomputation from
  // the disclosed snapshots. The record is a derived summary of the
  // pinned samples, not part of the report hash, so this check is
  // what stops a report from misstating it. A report that claims no
  // sampling evidence passes vacuously; a wide interval is a warning
  // in the detail, never a failure — thin evidence, not false.
  try {
    const hasSamples = snapshots.some((s) => Array.isArray(s.balanceSamples) && s.balanceSamples.length > 0);
    if (report.sampling === null || report.sampling === undefined) {
      if (!hasSamples) {
        check('sampling', true, 'Report claims no sampling evidence, and the disclosure carries no balance samples.');
      } else {
        const again = describeSampling(bundle);
        check(
          'sampling',
          true,
          `Report claims no sampling metadata; the disclosure carries ${again.sampleCount} sampled balance reading(s) (recomputed, not claimed).`,
        );
      }
    } else {
      const again = describeSampling(bundle);
      const fields = [
        'windowHours',
        'intervalBlocks',
        'sampleCount',
        'oldestBlock',
        'newestBlock',
        'sampleTimestamps',
        'timestampSource',
        'lowestObservedSampledBalance',
        'completeness',
        'missingHeights',
        'samplesRequested',
        'wideIntervalWarning',
        'limitation',
      ];
      let failure = null;
      for (const field of fields) {
        if (canonicalJson(report.sampling[field]) !== canonicalJson(again[field])) {
          failure = `Sampling field ${field} differs (report: ${canonicalJson(report.sampling[field])}, recomputed: ${canonicalJson(again[field])}).`;
          break;
        }
      }
      if (failure) {
        check('sampling', false, failure);
      } else {
        let detail =
          `Sampling evidence reproduced from the disclosure snapshot: ${again.sampleCount} reading(s), ` +
          `interval ${again.intervalBlocks === null ? 'n/a' : `${again.intervalBlocks} blocks`}, completeness ${again.completeness}.`;
        if (again.wideIntervalWarning) {
          detail += ` WARNING: ${again.wideIntervalWarning.message}`;
        } else {
          detail += ' No wide-interval warning.';
        }
        check('sampling', true, detail);
      }
    }
  } catch (err) {
    check('sampling', false, `Sampling recomputation failed: ${err.message}`);
  }

  // f. Re-running the claims engine reproduces the report's claims.
  try {
    if (!Array.isArray(report.claims)) {
      check('claims', false, 'Report claims are not an array.');
    } else {
      const rerun = evaluateClaims(bundle, policy, nowNs);
      const byId = new Map(rerun.claims.map((c) => [c.id, c]));
      let failure = null;
      if (Array.isArray(report.disclosed)) {
        const disclosedIds = [...report.disclosed].sort();
        const claimIds = report.claims.map((c) => c.id).sort();
        if (JSON.stringify(disclosedIds) !== JSON.stringify(claimIds)) {
          failure = 'Report disclosed list does not match the report claims.';
        }
      }
      if (!failure) {
        for (const claim of report.claims) {
          const again = byId.get(claim.id);
          if (!again) {
            failure = `Claim ${claim.id} was not reproduced by the rerun.`;
            break;
          }
          if (again.passed !== claim.passed) {
            failure = `Claim ${claim.id} passed value differs (report: ${claim.passed}, rerun: ${again.passed}).`;
            break;
          }
          if (String(again.threshold) !== String(claim.threshold)) {
            failure = `Claim ${claim.id} threshold differs (report: ${claim.threshold}, rerun: ${again.threshold}).`;
            break;
          }
          // Legacy reports (pre-P3) carry the exact value: it must
          // match too. Predicate reports carry no value, and the
          // threshold + pass/fail above are the whole public claim —
          // the exact value is verified privately by the re-run.
          if (claim.value !== undefined && String(again.value) !== String(claim.value)) {
            failure = `Claim ${claim.id} value differs (report: ${claim.value}, rerun: ${again.value}).`;
            break;
          }
        }
      }
      if (failure) {
        check('claims', false, failure);
      } else {
        const predicate = report.claims.some((c) => c.value === undefined);
        check(
          'claims',
          true,
          predicate
            ? `All ${report.claims.length} disclosed claim(s) reproduced as predicates from the disclosure snapshot (thresholds and pass/fail match; exact values verified privately).`
            : `All ${report.claims.length} disclosed claim(s) reproduced exactly from the disclosure snapshot.`,
        );
      }
    }
  } catch (err) {
    check('claims', false, `Claim rerun failed: ${err.message}`);
  }

  // g. The deterministic score, when present, recomputes exactly.
  // Legacy reports (pre-P3) carry the exact value and per-component
  // points: they must match exactly. Predicate reports carry only
  // the version, band and component shapes (no value, no points):
  // the recomputed exact score must fall in the public band and its
  // components must match on id/label/max/measured. The exact value
  // is never printed for a predicate report — the band is the result.
  // A recompute that matches is kept for the score limits panel.
  let recomputedScore = null;
  try {
    if (report.score === null || report.score === undefined) {
      check('score', true, 'Report carries no score (not scored).');
    } else {
      const windows = {
        txWindowDays: policy.txWindowDays,
        volumeWindowDays: policy.volumeWindowDays,
        noFailedWindowDays: policy.noFailedWindowDays,
      };
      const again = computeScore(bundle, windows, nowNs, report.score.version);
      const stripPoints = (components) =>
        (components || []).map((c) => ({ id: c.id, label: c.label, max: c.max, measured: c.measured }));
      // Risk flags, counterparty summary and disclaimer are compared
      // too — but only when the report carries them. Reports published
      // before Phase 3 carry none, and are not penalised for it.
      const extraMismatch = (reported, recomputed) => {
        if (reported.riskFlags !== undefined && JSON.stringify(reported.riskFlags) !== JSON.stringify(recomputed.riskFlags)) {
          return 'Score risk flags differ on rerun.';
        }
        if (
          reported.counterpartySummary !== undefined &&
          JSON.stringify(reported.counterpartySummary) !== JSON.stringify(recomputed.counterpartySummary)
        ) {
          return 'Score counterparty summary differs on rerun.';
        }
        if (reported.disclaimer !== undefined && reported.disclaimer !== recomputed.disclaimer) {
          return 'Score disclaimer differs on rerun.';
        }
        return null;
      };
      const flagSuffix = (recomputed) =>
        recomputed.riskFlags.length > 0
          ? ` Risk flags: ${recomputed.riskFlags.length} (${recomputed.riskFlags.map((f) => `${f.type}, ${f.severity}`).join('; ')}).`
          : '';
      let same = false;
      let detail = '';
      if (report.score.value !== undefined && report.score.value !== null) {
        same =
          again.version === report.score.version &&
          again.value === report.score.value &&
          again.band === report.score.band &&
          JSON.stringify(again.components) === JSON.stringify(report.score.components);
        if (same) {
          const mismatch = extraMismatch(report.score, again);
          if (mismatch !== null) {
            same = false;
            detail = mismatch;
          } else {
            detail = `Score recomputed exactly: ${again.value} (${again.band}).${flagSuffix(again)}`;
          }
        } else {
          detail = `Score differs on rerun (report: ${report.score.value}, rerun: ${again.value}).`;
        }
      } else {
        same =
          again.version === report.score.version &&
          again.band === report.score.band &&
          JSON.stringify(stripPoints(again.components)) === JSON.stringify(stripPoints(report.score.components));
        if (same) {
          const mismatch = extraMismatch(report.score, again);
          if (mismatch !== null) {
            same = false;
            detail = mismatch;
          } else {
            detail = `Score recomputed from the disclosure snapshot: band ${again.band} (matches the public band).${flagSuffix(again)}`;
          }
        } else {
          detail = `Score band differs on rerun (report band: ${report.score.band}, rerun band: ${again.band}).`;
        }
      }
      if (same) {
        recomputedScore = again;
        check('score', true, detail);
      } else {
        check('score', false, detail);
      }
    }
  } catch (err) {
    check('score', false, `Score rerun failed: ${err.message}`);
  }

  // h. Every linked wallet proves ownership (transfer or signature).
  {
    if (linked.length === 0) {
      check('link_proofs', true, 'No linked wallets to prove.');
    } else {
      const allTxs = snapshots.flatMap((s) => s.txs || []);
      const bindings = isObject(linkKeyBindings) ? linkKeyBindings : {};
      let failure = null;
      let methods = { transfer: 0, signature: 0 };
      for (let i = 0; i < linked.length; i += 1) {
        const entry = linked[i];
        if (!entry || typeof entry !== 'object') {
          failure = `Linked wallet ${i} has no link proof.`;
          break;
        }
        if (typeof entry.linkTxHash === 'string' && entry.linkTxHash.length > 0) {
          const tx = allTxs.find((t) => t.hash === entry.linkTxHash);
          if (!tx || tx.senderId !== entry.address || tx.receiverId !== disclosurePackage.address || tx.status !== 'Success') {
            failure = `Linked wallet ${i} has no successful linking transfer to the primary address.`;
            break;
          }
          methods.transfer += 1;
          continue;
        }
        if (entry.linkSignature && typeof entry.linkSignature === 'object') {
          const sig = entry.linkSignature;
          if (sig.message !== buildLinkMessage(entry.address, disclosurePackage.address)) {
            failure = `Linked wallet ${i} signature is not the link statement for this pairing.`;
            break;
          }
          if (bindings[entry.address] !== sig.publicKey) {
            failure = `Linked wallet ${i} has no verified public key binding (the key was not confirmed against the chain access key list).`;
            break;
          }
          if (!verifyLinkSignature(sig)) {
            failure = `Linked wallet ${i} link signature does not verify.`;
            break;
          }
          methods.signature += 1;
          continue;
        }
        failure = `Linked wallet ${i} has no link proof (neither a linking transfer nor a link signature).`;
        break;
      }
      if (failure) {
        check('link_proofs', false, failure);
      } else {
        const parts = [];
        if (methods.transfer > 0) parts.push(`${methods.transfer} by transfer`);
        if (methods.signature > 0) parts.push(`${methods.signature} by signature`);
        check('link_proofs', true, `All ${linked.length} linked wallet(s) proved ownership (${parts.join(', ')}).`);
      }
    }
  }

  // i. Unexpired and still valid onchain.
  {
    const reasons = [];
    try {
      if (!(now < BigInt(report.expiresAt))) reasons.push('Report expired.');
    } catch {
      reasons.push('Report expiry unreadable.');
    }
    if (onchainRecord.valid === false) {
      reasons.push('Registry reports the claim invalid (revoked, expired, or missing).');
    } else if (onchainRecord.valid !== true) {
      reasons.push('Registry validity result missing.');
    }
    if (reasons.length === 0) {
      check('validity', true, 'Report is unexpired and the registry reports the claim valid.');
    } else {
      check('validity', false, reasons.join(' '));
    }
  }

  // --- Five separate statuses, derived from the ten checks ---
  // Source: the disclosed snapshot reproduces the committed data hash.
  const source_status = checkPassed(checks, 'data_hash')
    ? {
        status: 'VERIFIED',
        detail: 'Blockchain data retrieved and processed: the disclosed snapshot reproduces the data hash committed onchain at publication.',
      }
    : { status: 'FAILED', detail: (checks.find((c) => c.check === 'data_hash') || {}).detail || 'The data hash check failed.' };

  // Computation: claims, score, sampling record and link proofs
  // rerun from the snapshot.
  const computationFailed = ['claims', 'score', 'sampling', 'link_proofs'].filter((name) => !checkPassed(checks, name));
  const computation_status =
    computationFailed.length === 0
      ? {
          status: 'VERIFIED',
          detail: 'Calculations independently reproduced: the claims, the deterministic score, the sampling record and the wallet link proofs were rerun from the disclosure snapshot and match the report.',
        }
      : { status: 'FAILED', detail: `The rerun did not reproduce the report: ${computationFailed.join(', ')} failed.` };

  // Report integrity: hashes, binding, expiry and registry validity.
  // Tampering outranks expiry: a report that does not match its
  // published record is FAILED even if it is also expired.
  let report_integrity_status;
  const integrityFailed = ['prover_binding', 'report_hash', 'evidence_hash', 'policy_hash'].filter(
    (name) => !checkPassed(checks, name),
  );
  let expiredByTime = false;
  try {
    expiredByTime = !(now < BigInt(report.expiresAt));
  } catch {
    expiredByTime = false;
  }
  if (integrityFailed.length > 0) {
    report_integrity_status = {
      status: 'FAILED',
      detail: `The report does not match its published record: ${integrityFailed.join(', ')} failed.`,
    };
  } else if (expiredByTime) {
    report_integrity_status = { status: 'EXPIRED', detail: 'The report is past its expiry date.' };
  } else if (onchainRecord.valid === false) {
    report_integrity_status = {
      status: 'REVOKED',
      detail: 'The registry reports the claim invalid (revoked, expired, or missing).',
    };
  } else if (!checkPassed(checks, 'validity')) {
    report_integrity_status = {
      status: 'UNVERIFIED',
      detail: 'The registry did not confirm the claim valid, so revocation could not be checked.',
    };
  } else {
    report_integrity_status = {
      status: 'VERIFIED',
      detail: 'The report is exactly what was published: the report, evidence and policy hashes match the onchain record, the disclosure belongs to this report, and the registry still reports the claim valid.',
    };
  }

  // Privacy: what the PUBLIC report discloses, not what the verifier
  // sees. The verifier holds the disclosure package, so the verifier
  // sees the address and the exact values.
  let privacy_status;
  const hasExactValues =
    (Array.isArray(report.claims) && report.claims.some((c) => c && c.value !== undefined)) ||
    (report.score !== null &&
      report.score !== undefined &&
      report.score.value !== undefined &&
      report.score.value !== null);
  const salted = typeof disclosurePackage.salt === 'string' && /^[0-9a-f]{32}$/.test(disclosurePackage.salt);
  const addressInReport =
    (typeof report.prover === 'string' && report.prover.length > 0 && !SHA256_HEX.test(report.prover)) ||
    typeof report.address === 'string';
  if (addressInReport) {
    privacy_status = { status: 'PUBLIC', detail: 'The public report itself names the wallet address.' };
  } else if (hasExactValues || !salted) {
    const reasons = [];
    if (hasExactValues) reasons.push('the public report discloses exact values');
    if (!salted) {
      reasons.push('the wallet commitment has no fresh salt, so two reports from the same wallet share one commitment and can be matched');
    }
    privacy_status = { status: 'PARTIALLY_DISCLOSED', detail: `Partly disclosed: ${reasons.join(' and ')}.` };
  } else {
    privacy_status = {
      status: 'PRIVATE',
      detail: 'Private from the public: the published report carries thresholds and a score band only, no exact values, and the wallet commitment uses a fresh salt, so two reports cannot be matched by their commitments. The address itself never appears in the public report.',
    };
  }

  // Attestation: from the supplied attestation result when present,
  // otherwise derived from the report AI summary alone (which can
  // never reach VERIFIED, see deriveAttestationStatus).
  const attestation_status = deriveAttestationStatus(attestation, report, nowNs);

  // Sampling and score limits: descriptive derivations from the
  // disclosure. A derivation that cannot run yields null, and the
  // panel renders that as not available rather than inventing one.
  // The sampling record is describeSampling on the bundle — the same
  // record the report carries and the `sampling` check verifies.
  let sampling = null;
  try {
    sampling = describeSampling(bundle);
  } catch {
    sampling = null;
  }
  let score = null;
  try {
    if (recomputedScore) {
      const stripPoints = (components) =>
        (components || []).map((c) => ({ id: c.id, label: c.label, max: c.max, measured: c.measured }));
      score = {
        version: recomputedScore.version,
        band: recomputedScore.band,
        components: stripPoints(recomputedScore.components),
        riskFlags: recomputedScore.riskFlags,
        counterpartyLabels: recomputedScore.counterpartyLabels,
        counterpartySummary: recomputedScore.counterpartySummary,
        disclaimer: recomputedScore.disclaimer,
      };
    }
  } catch {
    score = null;
  }

  return {
    valid: checks.every((c) => c.passed),
    checks,
    source_status,
    computation_status,
    attestation_status,
    report_integrity_status,
    privacy_status,
    sampling,
    score,
  };
}
