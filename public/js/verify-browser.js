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
import { evaluateClaims } from './claims-engine.js';
import { computeDataHash } from './onchain.js';
import { reportHash, evidenceHash, policyHash } from './report.js';

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function shortHash(hash) {
  return typeof hash === 'string' ? hash : '(missing)';
}

export async function verifyReport({ report, onchainRecord, disclosurePackage, policy, nowNs }) {
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
  } else if ((await sha256Hex(disclosurePackage.address)) !== report.prover) {
    check('prover_binding', false, 'Disclosure address does not hash to the report prover commitment.');
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

  // d. The disclosed snapshot reproduces the committed data hash.
  try {
    const snap = disclosurePackage.snapshot;
    const computed = await computeDataHash(snap.account.accountId, snap.account.amount, snap.account.locked, snap.txs);
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
