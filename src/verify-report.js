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
// - claims: re-running the claims engine on the disclosed snapshot(s)
//   under the disclosed policy reproduces the report's claims
//   (same ids, same passed, same values). Claims the prover chose
//   NOT to disclose are simply absent from the report; the re-run may
//   contain more claims than the report, and that is fine.
// - score: when the report carries a deterministic score, recomputing
//   it from the disclosed snapshots under the disclosed policy
//   reproduces it exactly (same value, band and components). A report
//   without a score passes vacuously ("not scored").
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
import { evaluateClaims } from './claims-engine.js';
import { dataHashForSnapshots } from './onchain.js';
import { computeScore } from './score.js';
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

export function verifyReport({ report, onchainRecord, disclosurePackage, policy, nowNs, linkKeyBindings }) {
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

  // e. Re-running the claims engine reproduces the report's claims.
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

  // f. The deterministic score, when present, recomputes exactly.
  // Legacy reports (pre-P3) carry the exact value and per-component
  // points: they must match exactly. Predicate reports carry only
  // the version, band and component shapes (no value, no points):
  // the recomputed exact score must fall in the public band and its
  // components must match on id/label/max/measured. The exact value
  // is never printed for a predicate report — the band is the result.
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
      let same = false;
      let detail = '';
      if (report.score.value !== undefined && report.score.value !== null) {
        same =
          again.version === report.score.version &&
          again.value === report.score.value &&
          again.band === report.score.band &&
          JSON.stringify(again.components) === JSON.stringify(report.score.components);
        detail = same
          ? `Score recomputed exactly: ${again.value} (${again.band}).`
          : `Score differs on rerun (report: ${report.score.value}, rerun: ${again.value}).`;
      } else {
        same =
          again.version === report.score.version &&
          again.band === report.score.band &&
          JSON.stringify(stripPoints(again.components)) === JSON.stringify(stripPoints(report.score.components));
        detail = same
          ? `Score recomputed from the disclosure snapshot: band ${again.band} (matches the public band).`
          : `Score band differs on rerun (report band: ${report.score.band}, rerun band: ${again.band}).`;
      }
      if (same) {
        check('score', true, detail);
      } else {
        check('score', false, detail);
      }
    }
  } catch (err) {
    check('score', false, `Score rerun failed: ${err.message}`);
  }

  // g. Every linked wallet proves ownership (transfer or signature).
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

  // h. Unexpired and still valid onchain.
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
