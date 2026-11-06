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
import { saltedAddressHash } from './report.js';
import { buildLinkMessage, verifyLinkSignature } from './nep413.js';

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

const SALT_HEX = /^[0-9a-f]{32}$/;

// The commitment a disclosure address must match. With a salt (P2)
// it is the salted commitment; without one it is the legacy plain
// sha256(address) of pre-P2 reports. Mirror of src/disclosure.js.
async function addressMatchesCommitment(address, salt, commitment) {
  if (salt === undefined || salt === null) return (await sha256Hex(address)) === commitment;
  return (await saltedAddressHash(salt, address)) === commitment;
}

function requireSalt(salt, label) {
  if (typeof salt !== 'string' || !SALT_HEX.test(salt)) {
    throw new Error(`disclosure: ${label} must be 32 lowercase hex chars (16 random bytes)`);
  }
  return salt;
}

// Assemble the private disclosure package for one chosen verifier.
// The snapshot is deep-copied so later mutation of the caller's
// snapshot cannot silently change what was disclosed.
// salt (optional, P2): the fresh per-report salt. When given, the
// package carries it and the binding check is the salted commitment;
// when omitted, the legacy plain sha256(address) check applies (old
// reports keep working).
export async function buildDisclosurePackage(report, address, snapshot, salt) {
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
  if (salt !== undefined && salt !== null) requireSalt(salt, 'salt');
  if (!(await addressMatchesCommitment(address, salt, report.prover))) {
    throw new Error('buildDisclosurePackage: address does not hash to report.prover');
  }
  const pkg = {
    address,
    dataHash: snapshot.dataHash,
    reportId: report.reportId,
    snapshot: JSON.parse(JSON.stringify(snapshot)),
  };
  if (salt !== undefined && salt !== null) pkg.salt = salt;
  return pkg;
}

// Assemble the private disclosure package for a multi-wallet report.
// linked is an array of { address, snapshot, linkTxHash } or
// { address, snapshot, linkSignature } — one entry per additional
// wallet, with exactly one proof per wallet:
// - linkTxHash: the hash of the linking transfer FROM that wallet TO
//   the primary address. Costs gas and leaves a public onchain
//   record connecting the two wallets.
// - linkSignature: a NEP-413 signature over the link statement for
//   this exact pairing (see ./nep413.js). Same ownership proof,
//   no transfer, no gas, no public onchain link between the wallets.
//   The signature is verified cryptographically here (fail fast); the
//   binding of its public key to the linked account is checked by
//   the verifier via the chain's access key list (linkKeyBindings).
// Each linked address must hash to an entry in report.linkedProvers.
// salt (optional, P2): the primary wallet's fresh per-report salt,
// passed through to buildDisclosurePackage. Each linked entry may
// carry its own `salt` (fresh per linked wallet per report); the
// entry's binding check is salted when present, legacy plain when not.
export async function buildMultiDisclosurePackage(report, address, snapshot, linked = [], salt) {
  const base = await buildDisclosurePackage(report, address, snapshot, salt);
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
    const entrySalt = entry.salt === undefined || entry.salt === null ? undefined : requireSalt(entry.salt, `linked[${i}].salt`);
    if (!(await addressMatchesCommitment(entry.address, entrySalt, linkedProvers[i]))) {
      throw new Error(`buildMultiDisclosurePackage: linked[${i}].address does not hash to report.linkedProvers[${i}]`);
    }
    const hasTx = typeof entry.linkTxHash === 'string' && entry.linkTxHash.length > 0;
    const hasSig = entry.linkSignature !== undefined && entry.linkSignature !== null;
    if (hasTx === hasSig) {
      throw new Error(`buildMultiDisclosurePackage: linked[${i}] must carry exactly one of linkTxHash or linkSignature`);
    }
    if (hasTx) {
      const tx = entry.snapshot.txs.find((t) => t.hash === entry.linkTxHash);
      if (!tx || tx.senderId !== entry.address || tx.receiverId !== address || tx.status !== 'Success') {
        throw new Error(
          `buildMultiDisclosurePackage: linked[${i}].linkTxHash is not a successful transfer from the linked wallet to the primary address`,
        );
      }
      const outTx = {
        address: entry.address,
        linkTxHash: entry.linkTxHash,
        snapshot: JSON.parse(JSON.stringify(entry.snapshot)),
      };
      if (entrySalt !== undefined) outTx.salt = entrySalt;
      entries.push(outTx);
      continue;
    }
    const sig = entry.linkSignature;
    if (!sig || typeof sig !== 'object') {
      throw new Error(`buildMultiDisclosurePackage: linked[${i}].linkSignature must be an object`);
    }
    for (const field of ['message', 'nonce', 'recipient', 'signature', 'publicKey']) {
      if (typeof sig[field] !== 'string' || sig[field].length === 0) {
        throw new Error(`buildMultiDisclosurePackage: linked[${i}].linkSignature.${field} must be a non-empty string`);
      }
    }
    if (sig.message !== buildLinkMessage(entry.address, address)) {
      throw new Error(`buildMultiDisclosurePackage: linked[${i}].linkSignature.message is not the link statement for this pairing`);
    }
    if (!(await verifyLinkSignature(sig))) {
      throw new Error(`buildMultiDisclosurePackage: linked[${i}].linkSignature does not verify`);
    }
    const outSig = {
      address: entry.address,
      linkSignature: { ...sig },
      snapshot: JSON.parse(JSON.stringify(entry.snapshot)),
    };
    if (entrySalt !== undefined) outSig.salt = entrySalt;
    entries.push(outSig);
  }
  return { ...base, linked: entries };
}

// Throw if the public report's canonical JSON contains the raw address
// or any of the given transaction hashes. Pass the address and the
// snapshot's tx hashes (as strings). The prover commitment (a hash)
// is SUPPOSED to be in the report and is not checked.
// salts (optional, P2): the per-report salt(s) — a string or an array.
// A salt must never appear in the public report either; if it does,
// the report is linkable by dictionary attack again, so refuse it.
export function assertPublicReportClean(report, address, txHashes, salts) {
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
  const saltList = salts === undefined || salts === null ? [] : Array.isArray(salts) ? salts : [salts];
  for (const salt of saltList) {
    if (typeof salt !== 'string' || salt.length === 0) continue;
    if (json.includes(salt)) {
      throw new Error('assertPublicReportClean: report leaks a prover salt');
    }
  }
  // P3 predicate disclosure — mirror of src/disclosure.js: a public
  // report must not carry exact values (no claim `value`, no score
  // `value`, no component `points`).
  for (const claim of Array.isArray(report.claims) ? report.claims : []) {
    if (claim && typeof claim === 'object' && claim.value !== undefined) {
      throw new Error(`assertPublicReportClean: report leaks the exact value of claim ${claim.id}`);
    }
  }
  if (report.score && typeof report.score === 'object') {
    if (report.score.value !== undefined) {
      throw new Error('assertPublicReportClean: report leaks the exact score value');
    }
    for (const comp of Array.isArray(report.score.components) ? report.score.components : []) {
      if (comp && typeof comp === 'object' && comp.points !== undefined) {
        throw new Error(`assertPublicReportClean: report leaks the exact points of score component ${comp.id}`);
      }
    }
  }
  return true;
}
