// VeilProof selective disclosure — Node side.
//
// The disclosure package is the ONLY place the prover's address ever
// appears. It travels privately to the single verifier the prover
// chose (a lender, an auditor), never onchain, never in the public
// report, never in a log. Anyone holding it can re-fetch the chain data
// for that address and re-run the claims — that is what makes the
// input genuine: the verifier checks the chain, not the prover's word.
//
// Two functions here:
// - buildDisclosurePackage: assembles the private package, and refuses
//   to build one whose address does not hash to the report's prover
//   commitment (a package for the wrong report is a caller error).
// - assertPublicReportClean: a tripwire for the public report. Call it
//   before sharing or publishing a report: it throws if the report's
//   canonical JSON contains the raw address or any transaction hash
//   from the snapshot. The report must never leak them.

import { createHash } from 'node:crypto';
import { canonicalJson } from './canonical.js';

const SHA256_HEX = /^[0-9a-f]{64}$/;

function sha256Hex(str) {
  return createHash('sha256').update(str, 'utf8').digest('hex');
}

function requireSnapshot(snapshot) {
  if (!snapshot || typeof snapshot !== 'object' || Array.isArray(snapshot)) {
    throw new Error('disclosure: snapshot must be an object');
  }
  if (!snapshot.account || typeof snapshot.account !== 'object') {
    throw new Error('disclosure: snapshot.account is missing');
  }
  if (!Array.isArray(snapshot.txs)) {
    throw new Error('disclosure: snapshot.txs must be an array');
  }
  if (typeof snapshot.dataHash !== 'string' || !SHA256_HEX.test(snapshot.dataHash)) {
    throw new Error('disclosure: snapshot.dataHash must be a 64-char lowercase hex SHA-256');
  }
  return snapshot;
}

// Assemble the private disclosure package for one chosen verifier.
// The snapshot is deep-copied so later mutation of the caller's
// snapshot cannot silently change what was disclosed.
export function buildDisclosurePackage(report, address, snapshot) {
  if (!report || typeof report !== 'object' || Array.isArray(report)) {
    throw new Error('buildDisclosurePackage: report must be an object');
  }
  if (typeof report.reportId !== 'string' || report.reportId.length === 0) {
    throw new Error('buildDisclosurePackage: report.reportId must be a non-empty string');
  }
  if (typeof address !== 'string' || address.length === 0) {
    throw new Error('buildDisclosurePackage: address must be a non-empty string');
  }
  requireSnapshot(snapshot);
  if (sha256Hex(address) !== report.prover) {
    throw new Error('buildDisclosurePackage: address does not hash to report.prover');
  }
  return {
    address,
    dataHash: snapshot.dataHash,
    reportId: report.reportId,
    snapshot: JSON.parse(JSON.stringify(snapshot)),
  };
}

// Throw if the public report's canonical JSON contains the raw address
// or any of the given transaction hashes. Pass the address and the
// snapshot's tx hashes (as strings). The prover commitment (a hash)
// is SUPPOSED to be in the report and is not checked.
export function assertPublicReportClean(report, address, txHashes) {
  if (!report || typeof report !== 'object' || Array.isArray(report)) {
    throw new Error('assertPublicReportClean: report must be an object');
  }
  if (!Array.isArray(txHashes)) {
    throw new Error('assertPublicReportClean: txHashes must be an array');
  }
  // Canonical JSON is the exact bytes that get hashed and shared, so
  // checking it (not a pretty-printed form) is checking what leaves.
  const json = canonicalJson(report);
  if (typeof address === 'string' && address.length > 0 && json.includes(address)) {
    throw new Error('assertPublicReportClean: report leaks the prover address');
  }
  for (const hash of txHashes) {
    if (typeof hash !== 'string' || hash.length === 0) continue;
    if (json.includes(hash)) {
      throw new Error(`assertPublicReportClean: report leaks transaction hash ${hash}`);
    }
  }
  return true;
}
