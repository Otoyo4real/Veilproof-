// VeilProof selective disclosure — BROWSER mirror of src/disclosure.js.
//
// Same rules as the Node module: the disclosure package is the ONLY
// place the prover's address ever appears; buildDisclosurePackage
// refuses a package whose address does not hash to the report's prover
// commitment; assertPublicReportClean is the tripwire that throws if
// the public report's canonical JSON contains the raw address or any
// transaction hash.
//
// Only the hash primitive differs: Web Crypto (async) instead of
// node:crypto, so buildDisclosurePackage is async here.
// TWO PATHS, kept in sync by the parity test in
// test/frontend-parity.test.mjs. Keep the two in sync.

import { canonicalJson } from './canonical.js';
import { sha256Hex } from './crypto.js';

const SHA256_HEX = /^[0-9a-f]{64}$/;

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
export async function buildDisclosurePackage(report, address, snapshot) {
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
  if ((await sha256Hex(address)) !== report.prover) {
    throw new Error('buildDisclosurePackage: address does not hash to report.prover');
  }
  return {
    address,
    dataHash: snapshot.dataHash,
    reportId: report.reportId,
    snapshot: JSON.parse(JSON.stringify(snapshot)),
  };
}

// Assemble the private disclosure package for a multi-wallet report.
// linked is an array of { address, snapshot, linkTxHash } — one entry
// per additional wallet. linkTxHash is the hash of the linking
// transfer FROM that wallet TO the primary address: only the key
// holder of the linked wallet could have signed it, so the transfer
// itself is the ownership proof (verified by verify-report.js).
// Each linked address must hash to an entry in report.linkedProvers,
// and each linking transfer must appear among the disclosed txs.
export async function buildMultiDisclosurePackage(report, address, snapshot, linked = []) {
  const base = await buildDisclosurePackage(report, address, snapshot);
  if (!Array.isArray(linked)) {
    throw new Error('buildMultiDisclosurePackage: linked must be an array');
  }
  const linkedProvers = Array.isArray(report.linkedProvers) ? report.linkedProvers : [];
  const entries = [];
  for (let i = 0; i < linked.length; i += 1) {
    const entry = linked[i];
    if (!entry || typeof entry !== 'object') {
      throw new Error(`buildMultiDisclosurePackage: linked[${i}] must be an object`);
    }
    if (typeof entry.address !== 'string' || entry.address.length === 0) {
      throw new Error(`buildMultiDisclosurePackage: linked[${i}].address must be a non-empty string`);
    }
    requireSnapshot(entry.snapshot);
    if ((await sha256Hex(entry.address)) !== linkedProvers[i]) {
      throw new Error(`buildMultiDisclosurePackage: linked[${i}].address does not hash to report.linkedProvers[${i}]`);
    }
    if (typeof entry.linkTxHash !== 'string' || entry.linkTxHash.length === 0) {
      throw new Error(`buildMultiDisclosurePackage: linked[${i}].linkTxHash must be a non-empty string`);
    }
    const tx = entry.snapshot.txs.find((t) => t.hash === entry.linkTxHash);
    if (!tx || tx.senderId !== entry.address || tx.receiverId !== address || tx.status !== 'Success') {
      throw new Error(
        `buildMultiDisclosurePackage: linked[${i}].linkTxHash is not a successful transfer from the linked wallet to the primary address`,
      );
    }
    entries.push({
      address: entry.address,
      linkTxHash: entry.linkTxHash,
      snapshot: JSON.parse(JSON.stringify(entry.snapshot)),
    });
  }
  return { ...base, linked: entries };
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
