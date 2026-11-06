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
// - data_hash: the snapshot the verifier was given reproduces the
//   data hash the report commits to. The snapshot's facts come from
//   the chain; anyone can re-fetch them for the disclosed address.
// - claims: re-running the claims engine on the disclosed snapshot
//   under the disclosed policy reproduces the report's claims
//   (same ids, same passed, same values). Claims the prover chose
//   NOT to disclose are simply absent from the report; the re-run may
//   contain more claims than the report, and that is fine.
// - validity: the report is unexpired and the registry still reports
//   the claim valid (not revoked, not expired, exists).
//
// What verification does NOT prove: that the chain data is "real" in
// some offchain sense — it is real because it is onchain and the
// verifier re-reads it. It does not prove anything about data that
// never touched the chain. And a null aiSummary means "not analysed":
// verification never requires an AI summary and never invents one.
//
// Failure policy: a failed check is recorded, never thrown. Only
// malformed input throws — a missing/non-object report, onchain
// record, disclosure package or policy, a missing disclosure
// snapshot, or an unusable nowNs. Everything about the CONTENT of
// those objects is a failed check, not an exception.

import { createHash } from 'node:crypto';
import { evaluateClaims } from './claims-engine.js';
import { computeDataHash } from './onchain.js';
import { reportHash, evidenceHash, policyHash } from './report.js';

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

export function verifyReport({ report, onchainRecord, disclosurePackage, policy, nowNs }) {
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

  // 0. The disclosure package belongs to this report.
  if (typeof disclosurePackage.address !== 'string' || disclosurePackage.address.length === 0) {
    check('prover_binding', false, 'Disclosure package has no address.');
  } else if (typeof report.prover !== 'string' || report.prover.length === 0) {
    check('prover_binding', false, 'Report has no prover commitment.');
  } else if (sha256Hex(disclosurePackage.address) !== report.prover) {
    check('prover_binding', false, 'Disclosure address does not hash to the report prover commitment.');
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

  // d. The disclosed snapshot reproduces the committed data hash.
  try {
    const snap = disclosurePackage.snapshot;
    const computed = computeDataHash(snap.account.accountId, snap.account.amount, snap.account.locked, snap.txs);
    const ref = report.evidenceRefs?.dataHash;
    if (computed === ref) {
      check('data_hash', true, 'Recomputed data hash matches the report evidence reference.');
    } else {
      check('data_hash', false, `Recomputed data hash ${computed} does not match report evidence reference ${shortHash(ref)}.`);
    }
  } catch (err) {
    check('data_hash', false, `Could not recompute data hash: ${err.message}`);
  }

  // e. Re-running the claims engine reproduces the report's claims.
  try {
    if (!Array.isArray(report.claims)) {
      check('claims', false, 'Report claims are not an array.');
    } else {
      const rerun = evaluateClaims(disclosurePackage.snapshot, policy, nowNs);
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
            failure = `Claim ${claim.id} was not reproduced by the re-run.`;
            break;
          }
          if (again.passed !== claim.passed) {
            failure = `Claim ${claim.id} passed value differs (report: ${claim.passed}, re-run: ${again.passed}).`;
            break;
          }
          if (String(again.value) !== String(claim.value)) {
            failure = `Claim ${claim.id} value differs (report: ${claim.value}, re-run: ${again.value}).`;
            break;
          }
        }
      }
      if (failure) {
        check('claims', false, failure);
      } else {
        check('claims', true, `All ${report.claims.length} disclosed claim(s) reproduced exactly from the disclosure snapshot.`);
      }
    }
  } catch (err) {
    check('claims', false, `Claim re-run failed: ${err.message}`);
  }

  // f. Unexpired and still valid onchain.
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

  return { valid: checks.every((c) => c.passed), checks };
}
