// VeilProof report verification — browser side (async, Web Crypto).
//
// An ES-module mirror of src/verify-report.js, composed from the
// existing browser modules (public/js/*) instead of duplicating their
// logic: sha256Hex from crypto.js, reportHash/evidenceHash/policyHash
// from report.js, computeDataHash from onchain.js, evaluateClaims from
// claims-engine.js. Check names, order and detail strings are
// identical to the Node module — test/verify-browser.test.mjs asserts
// identical verdicts on the same fixtures.
//
// NOTE: public/verify.html still carries its own inlined copy of this
// same logic (the parity test in test/verify-report.test.mjs runs that
// copy in a VM). The two browser copies must stay in sync: this module
// is the one the homepage live demo uses; the verifier portal keeps
// its inline copy so the portal works from a single file. If the
// checks ever change, change all three (src, this module, verify.html)
// and let both parity tests catch drift.

import { sha256Hex } from './crypto.js';
import { canonicalJson } from './canonical.js';
import { evaluateClaims, unionTxs } from './claims-engine.js';
import { dataHashForSnapshots } from './onchain.js';
import { computeScore } from './score.js';
import { describeSampling } from './sampling.js';
import { reportHash, evidenceHash, policyHash, saltedAddressHash } from './report.js';
import { buildLinkMessage, verifyLinkSignature } from './nep413.js';

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function shortHash(hash) {
  return typeof hash === 'string' ? hash : '(missing)';
}

// --- Verification model: five separate statuses ---
//
// A mirror of the same section in src/verify-report.js: the ten
// checks stay, plus one status field per question a verifier
// actually asks, each with its own state. The overall `valid`
// boolean stays as a clearly labelled summary (all ten required
// checks pass), but the fields are never combined into a stronger
// claim than the evidence supports. See src/verify-report.js for
// what each status means; the three copies must stay in sync, and
// the parity tests in test/verify-report.test.mjs and
// test/verify-browser.test.mjs compare the full result objects.

const SHA256_HEX = /^[0-9a-f]{64}$/;

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
  if (att.verifiable === true && nonceMatched === true) {
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
// statuses, never from the valid boolean alone. Mirror of
// summariseVerification in src/verify-report.js.
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

// Format a yoctoNEAR amount as NEAR, floored to 2 decimals so the
// display never overstates the amount. Pure display helper, used by
// the panel builder below.
export function formatNearYocto(yocto) {
  try {
    const value = BigInt(yocto);
    if (value < 0n) return 'unreadable';
    const hundredths = (value * 100n) / 10n ** 24n;
    const whole = hundredths / 100n;
    const cents = hundredths % 100n;
    if (cents === 0n) return `${whole} NEAR`;
    if (cents % 10n === 0n) return `${whole}.${cents / 10n} NEAR`;
    return `${whole}.${String(cents).padStart(2, '0')} NEAR`;
  } catch {
    return 'unreadable';
  }
}

function escHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function pillFor(status) {
  switch (status) {
    case 'VERIFIED':
      return { cls: 'ok', label: 'VERIFIED' };
    case 'PRIVATE':
      return { cls: 'ok', label: 'PRIVATE' };
    case 'UNVERIFIED':
      return { cls: 'warn', label: 'UNVERIFIED' };
    case 'PARTIALLY_DISCLOSED':
      return { cls: 'warn', label: 'PARTIALLY DISCLOSED' };
    case 'FAILED':
      return { cls: 'bad', label: 'FAILED' };
    case 'REVOKED':
      return { cls: 'bad', label: 'REVOKED' };
    case 'EXPIRED':
      return { cls: 'bad', label: 'EXPIRED' };
    case 'PUBLIC':
      return { cls: 'bad', label: 'PUBLIC' };
    default:
      return { cls: 'warn', label: 'UNVERIFIED' };
  }
}

function pillHtml(status) {
  const p = pillFor(status);
  return `<span class="pill ${p.cls}">${p.label}</span>`;
}

function statusRow(label, field) {
  const status = field && typeof field.status === 'string' ? field.status : 'UNVERIFIED';
  const detail = field && typeof field.detail === 'string' ? field.detail : 'Not available.';
  return `<div class="status-row"><div class="status-head"><strong>${label}</strong> ${pillHtml(status)}</div><div class="status-detail">${escHtml(detail)}</div></div>`;
}

// Pure panel builder: renders the six panel fragments from a
// verifier result and its report. No DOM access, so the homepage
// demo, the verifier portal and the tests all use this one builder.
// Mirror of the same builder inlined in public/verify.html — the
// two must produce identical HTML, and the frontend verify model
// test asserts it.
export function buildStatusPanelsHtml(result, report) {
  const summary = summariseVerification(result);
  let summaryHtml =
    statusRow('Source data', result.source_status) +
    statusRow('Calculations', result.computation_status) +
    statusRow('AI attestation', result.attestation_status) +
    statusRow('Report integrity', result.report_integrity_status) +
    statusRow('Privacy', result.privacy_status);
  if (summary.notes.length > 0) {
    summaryHtml += `<div class="status-notes">${summary.notes.map((n) => `<p>${escHtml(n)}</p>`).join('')}</div>`;
  }

  const privacy = result.privacy_status && typeof result.privacy_status === 'object' ? result.privacy_status : {};
  const pStatus = typeof privacy.status === 'string' ? privacy.status : 'UNVERIFIED';
  let privacyHtml = statusRow('Privacy status', privacy);
  privacyHtml += '<p>What the public sees: ';
  if (pStatus === 'PRIVATE') {
    privacyHtml += 'thresholds and a score band only, plus the salted wallet commitment. The address never appears in the public report.';
  } else if (pStatus === 'PARTIALLY_DISCLOSED') {
    privacyHtml += 'thresholds and a score band, plus the exact values or the unsalted commitment named above. The address itself is not in the public report, but more can be read from it than from a predicate report.';
  } else if (pStatus === 'PUBLIC') {
    privacyHtml += 'the wallet address itself, so this report does not keep the wallet private.';
  } else {
    privacyHtml += 'not known, the privacy status could not be determined.';
  }
  privacyHtml += '</p>';
  privacyHtml += '<p>What you, the verifier, see: the wallet address and the exact values, because the prover sent you the disclosure package. Do not republish them.</p>';
  privacyHtml += '<p>Known limit: the registry record names the publishing wallet as owner, and lists every claim that wallet published, so claims from one wallet can still be linked through the registry even though the report commitments cannot be matched.</p>';

  const att = result.attestation_status && typeof result.attestation_status === 'object' ? result.attestation_status : {};
  const triText = (v) => (v === true ? 'yes' : v === false ? 'no' : 'not checked');
  let attExpires = 'not stated';
  try {
    if (typeof att.expiresAt === 'string' && att.expiresAt) {
      attExpires = new Date(Number(BigInt(att.expiresAt) / 1000000n)).toISOString();
    }
  } catch {
    attExpires = 'not stated';
  }
  let attestationHtml = statusRow('Attestation status', att);
  attestationHtml +=
    '<div class="table-scroll"><table><tr><th>Check</th><th>Result</th></tr>' +
    `<tr><td>Method</td><td>${escHtml(att.method || 'not stated')}</td></tr>` +
    `<tr><td>Model</td><td>${escHtml(att.model || 'not stated')}</td></tr>` +
    `<tr><td>Nonce matched</td><td>${triText(att.nonceMatched)}</td></tr>` +
    `<tr><td>Quote verified</td><td>${triText(att.quoteVerified)}</td></tr>` +
    `<tr><td>Signature verified</td><td>${triText(att.signatureVerified)}</td></tr>` +
    `<tr><td>Measurements checked</td><td>${triText(att.measurementsChecked)}</td></tr>` +
    `<tr><td>Expires</td><td>${escHtml(attExpires)}</td></tr></table></div>`;
  attestationHtml += '<p>The attestation is the evidence that the AI analysis ran inside a trusted enclave. It is verified only when the nonce, the quote, the signature and the measurements were all checked. A nonce match on its own does not verify the attestation.</p>';

  const integ = result.report_integrity_status && typeof result.report_integrity_status === 'object' ? result.report_integrity_status : {};
  const iStatus = typeof integ.status === 'string' ? integ.status : 'UNVERIFIED';
  let expires = 'unreadable';
  try {
    expires = new Date(Number(BigInt(report.expiresAt) / 1000000n)).toISOString();
  } catch {
    expires = 'unreadable';
  }
  let integrityHtml = statusRow('Report integrity', integ);
  integrityHtml += `<p>Expires: <span class="mono">${escHtml(expires)}</span></p>`;
  if (iStatus === 'VERIFIED') {
    integrityHtml += '<p>The registry still reports the claim valid.</p>';
  } else if (iStatus === 'REVOKED') {
    integrityHtml += '<p>The registry reports the claim invalid. A revoked report must not be relied on, even if every other check passes.</p>';
  } else if (iStatus === 'EXPIRED') {
    integrityHtml += '<p>The report is past its expiry date. An expired report must not be relied on, even if every other check passes.</p>';
  } else if (iStatus === 'FAILED') {
    integrityHtml += '<p>The report does not match the onchain record, so it is not the report that was published.</p>';
  } else {
    integrityHtml += '<p>The registry did not confirm the claim, so revocation could not be checked.</p>';
  }

  const sampling = result.sampling;
  let samplingHtml;
  if (!sampling || sampling.completeness === 'none') {
    samplingHtml =
      '<p>No balance samples were disclosed with this report, so there is no sampled history to show.</p>' +
      '<p>Without samples, a sustained balance claim cannot be checked, because it needs readings at past block heights.</p>';
  } else {
    const completenessText =
      sampling.completeness === 'complete'
        ? 'complete: every requested reading is present'
        : sampling.completeness === 'partial'
          ? `partial: ${sampling.missingHeights && sampling.missingHeights.length > 0 ? `missing heights ${sampling.missingHeights.join(', ')}` : 'fewer readings than requested'}`
          : 'not known';
    const timestampsText = !sampling.sampleTimestamps
      ? 'not available'
      : `${sampling.sampleTimestamps.length} reading(s), times ${sampling.timestampSource === 'rpc' ? 'read from the chain' : sampling.timestampSource === 'estimated' ? 'estimated from block height' : 'unavailable'}`;
    samplingHtml =
      '<div class="table-scroll"><table><tr><th>Reading</th><th>Value</th></tr>' +
      `<tr><td>Sample count</td><td>${sampling.sampleCount}</td></tr>` +
      `<tr><td>Interval between samples</td><td>${sampling.intervalBlocks === null ? 'n/a' : `${sampling.intervalBlocks} blocks`}</td></tr>` +
      `<tr><td>Oldest sampled block</td><td>${sampling.oldestBlock}</td></tr>` +
      `<tr><td>Newest sampled block</td><td>${sampling.newestBlock}</td></tr>` +
      `<tr><td>Lowest observed sampled balance</td><td>${escHtml(formatNearYocto(sampling.lowestObservedSampledBalance))}</td></tr>` +
      `<tr><td>Completeness</td><td>${escHtml(completenessText)}</td></tr>` +
      `<tr><td>Sample times</td><td>${escHtml(timestampsText)}</td></tr>` +
      `<tr><td>Wide interval warning</td><td>${sampling.wideIntervalWarning ? 'yes' : 'no'}</td></tr></table></div>`;
    samplingHtml += '<p>Samples are balance readings at past block heights. The lowest observed sampled balance is what the sustained balance claim measures. Balances between samples are not observed, so a dip that starts and ends between two samples would not show here.</p>';
    if (sampling.wideIntervalWarning) {
      samplingHtml += `<p class="warn">Warning: ${escHtml(sampling.wideIntervalWarning.message)}</p>`;
    }
  }

  const score = result.score;
  // The landed disclaimer comes with the recomputed score; the
  // hardcoded text is only a fallback when the score did not recompute.
  const fallbackDisclaimer =
    '<p>The score measures observable onchain activity only. It is not a guarantee of repayment, and it does not establish real world identity, ownership of counterparties, or creditworthiness.</p>';
  let scoreHtml;
  if (!score) {
    if (report.score) {
      scoreHtml =
        `<p>Credit score: band ${escHtml(report.score.band)} (${escHtml(report.score.version || 'unversioned')}).</p>` +
        '<p>The score did not recompute from the disclosure, see the score check above. Do not rely on the band until the score reproduces.</p>' +
        fallbackDisclaimer;
    } else {
      scoreHtml = '<p>This report carries no credit score.</p>' + fallbackDisclaimer;
    }
  } else {
    scoreHtml = `<p>Credit score: band <strong>${escHtml(score.band)}</strong> (${escHtml(score.version)}), recomputed by this verifier from the disclosure snapshot.</p>`;
    scoreHtml +=
      '<div class="table-scroll"><table><tr><th>Component</th><th>Max</th><th>Measured</th></tr>' +
      score.components
        .map((c) => `<tr><td>${escHtml(c.label)}</td><td>${c.max}</td><td>${c.measured ? 'yes' : 'not measured'}</td></tr>`)
        .join('') +
      '</table></div>';
    if (score.riskFlags.length > 0) {
      scoreHtml +=
        '<p>Risk flags:</p><ul>' +
        score.riskFlags
          .map((f) => `<li><strong>${escHtml(f.type)}</strong> (${escHtml(f.severity)}): ${escHtml(f.detail)}</li>`)
          .join('') +
        '</ul>';
    } else {
      scoreHtml += '<p>No risk flags.</p>';
    }
    if (score.counterpartyLabels.length > 0) {
      scoreHtml +=
        '<p>Counterparties observed in the window:</p><ul>' +
        score.counterpartyLabels
          .map((l) => `<li><span class="mono">${escHtml(l.account)}</span>: ${escHtml(l.label)}</li>`)
          .join('') +
        '</ul>' +
        '<p>Labels: own means one of the prover\u2019s own wallets; suspicious means the account appears in a risk flag above; unknown means no identity or ownership evidence exists for that account, so independence is not assumed. The verifier cannot tell from an account id alone whether a counterparty is independent of the prover.</p>';
      if (score.counterpartySummary) {
        scoreHtml += `<p>Counterparty counts: ${score.counterpartySummary.own} own, ${score.counterpartySummary.unknown} unknown, ${score.counterpartySummary.suspicious} suspicious.</p>`;
      }
    } else {
      scoreHtml += '<p>No counterparties were observed in the window.</p>';
    }
    const disclaimer =
      '<p>' +
      escHtml(
        typeof score.disclaimer === 'string'
          ? score.disclaimer
          : 'The score measures observable onchain activity only. It is not a guarantee of repayment, and it does not establish real world identity, ownership of counterparties, or creditworthiness.'
      ) +
      '</p>';
    scoreHtml += disclaimer;
  }

  return {
    summary: summaryHtml,
    privacy: privacyHtml,
    attestation: attestationHtml,
    integrity: integrityHtml,
    sampling: samplingHtml,
    score: scoreHtml,
  };
}

export async function verifyReport({ report, onchainRecord, disclosurePackage, policy, nowNs, linkKeyBindings, attestation }) {
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
  // legacy plain sha256(address) of pre-P2 reports.
  const addressMatchesCommitment = async (address, salt, commitment) => {
    if (salt === undefined || salt === null) return (await sha256Hex(address)) === commitment;
    if (typeof salt !== 'string' || !/^[0-9a-f]{32}$/.test(salt)) return false;
    return (await saltedAddressHash(salt, address)) === commitment;
  };
  if (typeof disclosurePackage.address !== 'string' || disclosurePackage.address.length === 0) {
    check('prover_binding', false, 'Disclosure package has no address.');
  } else if (typeof report.prover !== 'string' || report.prover.length === 0) {
    check('prover_binding', false, 'Report has no prover commitment.');
  } else if (!(await addressMatchesCommitment(disclosurePackage.address, disclosurePackage.salt, report.prover))) {
    check('prover_binding', false, 'Disclosure address does not hash to the report prover commitment.');
  } else if (linked.length > 0) {
    const linkedProvers = Array.isArray(report.linkedProvers) ? report.linkedProvers : [];
    const okays = [];
    for (let i = 0; i < linked.length; i += 1) {
      const entry = linked[i];
      okays.push(
        typeof entry?.address === 'string' && entry.address.length > 0
          ? await addressMatchesCommitment(entry.address, entry.salt, linkedProvers[i])
          : false,
      );
    }
    const bad = okays.findIndex((ok) => !ok);
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
    const computed = await reportHash(report);
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
    const computed = await evidenceHash(report.evidenceRefs);
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
    const computed = await policyHash(report.policyVersion, policy);
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
    const computed = await dataHashForSnapshots(snapshots);
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
          // match too. Predicate reports carry no value.
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
  // the version, band and component shapes: the recomputed exact
  // score must fall in the public band. The exact value is never
  // printed for a predicate report.
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
      const methods = { transfer: 0, signature: 0 };
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
          if (!(await verifyLinkSignature(sig))) {
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
  // Mirror of the same section in src/verify-report.js. The three
  // copies must stay in sync; the parity tests compare the full
  // result objects.
  const source_status = checkPassed(checks, 'data_hash')
    ? {
        status: 'VERIFIED',
        detail: 'Blockchain data retrieved and processed: the disclosed snapshot reproduces the data hash committed onchain at publication.',
      }
    : { status: 'FAILED', detail: (checks.find((c) => c.check === 'data_hash') || {}).detail || 'The data hash check failed.' };

  const computationFailed = ['claims', 'score', 'sampling', 'link_proofs'].filter((name) => !checkPassed(checks, name));
  const computation_status =
    computationFailed.length === 0
      ? {
          status: 'VERIFIED',
          detail: 'Calculations independently reproduced: the claims, the deterministic score, the sampling record and the wallet link proofs were rerun from the disclosure snapshot and match the report.',
        }
      : { status: 'FAILED', detail: `The rerun did not reproduce the report: ${computationFailed.join(', ')} failed.` };

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

  const attestation_status = deriveAttestationStatus(attestation, report, nowNs);

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
