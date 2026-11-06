// VeilProof verification tests — pure, no network.
// The registry is NOT called here: the caller fetches the onchain
// record and passes it in, so every case below is deterministic.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';
import { evaluateClaims } from '../src/claims-engine.js';
import { computeScore } from '../src/score.js';
import { computeDataHash, dataHashForSnapshots } from '../src/onchain.js';
import { buildReport, reportHash, evidenceHash, policyHash } from '../src/report.js';
import { buildDisclosurePackage, buildMultiDisclosurePackage } from '../src/disclosure.js';
import { verifyReport } from '../src/verify-report.js';
import { signLinkMessage, buildLinkMessage, base58Encode } from '../src/nep413.js';
import nacl from 'tweetnacl';

const ADDRESS = 'alice.veilproof.testnet';
const NOW_NS = 1793961600000000000n;
const DAY_NS = 86400n * 1_000_000_000n;
const EXPIRES_AT = (NOW_NS + 365n * DAY_NS).toString();
const POLICY_VERSION = 'veilproof-policy-v1';
const POLICY = {
  balanceAtLeastYocto: '1000000000000000000000000',
  stakedAtLeastYocto: '1000000000000000000000000',
  minTxCount: 1,
  txWindowDays: 30,
  minVolumeYocto: '1000000000000000000000000',
  volumeWindowDays: 30,
  noFailedWindowDays: 30,
};
const CHECK_ORDER = ['prover_binding', 'report_hash', 'evidence_hash', 'policy_hash', 'data_hash', 'claims', 'score', 'link_proofs', 'validity'];

function sha256Hex(s) {
  return createHash('sha256').update(s, 'utf8').digest('hex');
}

function tx(overrides = {}) {
  return {
    hash: 'A'.repeat(43),
    senderId: ADDRESS,
    receiverId: 'bob.veilproof.testnet',
    amountYocto: '1000000000000000000000000',
    status: 'Success',
    blockHeight: 100,
    blockTimestampNs: (NOW_NS - 10n * DAY_NS).toString(),
    ...overrides,
  };
}

function snapshot(overrides = {}) {
  const base = {
    account: {
      accountId: ADDRESS,
      amount: '5000000000000000000000000',
      locked: '2000000000000000000000000',
      storage_usage: 1000,
      blockHeight: 100,
    },
    txs: [
      tx({ hash: 'A'.repeat(43) }),
      tx({
        hash: 'B'.repeat(43),
        senderId: 'carol.veilproof.testnet',
        receiverId: ADDRESS,
        amountYocto: '500000000000000000000000',
        blockTimestampNs: (NOW_NS - 5n * DAY_NS).toString(),
      }),
    ],
    blockHeight: 100,
  };
  const snap = { ...base, ...overrides };
  snap.dataHash = computeDataHash(snap.account.accountId, snap.account.amount, snap.account.locked, snap.txs);
  return snap;
}

function onchainRecordFor(report, { valid = true } = {}) {
  return {
    report_hash: reportHash(report),
    evidence_hash: evidenceHash(report.evidenceRefs),
    policy_hash: policyHash(POLICY_VERSION, POLICY),
    valid,
  };
}

// A genuine case: all five claims pass, nothing expired or revoked.
function genuine() {
  const snap = snapshot();
  const { claims } = evaluateClaims(snap, POLICY, NOW_NS);
  const report = buildReport({
    proverAddressHash: sha256Hex(ADDRESS),
    claims,
    policyVersion: POLICY_VERSION,
    aiSummary: null,
    evidenceRefs: { dataHash: snap.dataHash, attestationRef: null },
    expiresAt: EXPIRES_AT,
  });
  return {
    address: ADDRESS,
    snapshot: snap,
    report,
    onchainRecord: onchainRecordFor(report),
    disclosurePackage: buildDisclosurePackage(report, ADDRESS, snap),
    policy: POLICY,
    nowNs: NOW_NS,
  };
}

function checkByName(result, name) {
  const found = result.checks.find((c) => c.check === name);
  assert.ok(found, `expected a ${name} check`);
  return found;
}

test('verify happy path: genuine report verifies valid, checks in order', () => {
  const g = genuine();
  const result = verifyReport({
    report: g.report,
    onchainRecord: g.onchainRecord,
    disclosurePackage: g.disclosurePackage,
    policy: g.policy,
    nowNs: g.nowNs,
  });
  assert.equal(result.valid, true);
  assert.deepEqual(result.checks.map((c) => c.check), CHECK_ORDER);
  assert.ok(result.checks.every((c) => c.passed));
  // Null AI summary is allowed: verification never requires analysis.
  assert.equal(g.report.aiSummary, null);
});

test('verify tamper: one altered claim fails the report hash', () => {
  const g = genuine();
  const tampered = JSON.parse(JSON.stringify(g.report));
  tampered.claims[0].value = '1';
  const result = verifyReport({
    report: tampered,
    onchainRecord: g.onchainRecord,
    disclosurePackage: g.disclosurePackage,
    policy: g.policy,
    nowNs: g.nowNs,
  });
  assert.equal(result.valid, false);
  assert.equal(checkByName(result, 'report_hash').passed, false);
  assert.equal(checkByName(result, 'claims').passed, false);
});

test('verify wrong dataHash: evidence and data checks fail', () => {
  const g = genuine();
  const tampered = JSON.parse(JSON.stringify(g.report));
  tampered.evidenceRefs.dataHash = '0'.repeat(64);
  const result = verifyReport({
    report: tampered,
    onchainRecord: g.onchainRecord,
    disclosurePackage: g.disclosurePackage,
    policy: g.policy,
    nowNs: g.nowNs,
  });
  assert.equal(result.valid, false);
  assert.equal(checkByName(result, 'evidence_hash').passed, false);
  assert.equal(checkByName(result, 'data_hash').passed, false);
});

test('verify wrong address: prover binding fails, everything else passes', () => {
  const g = genuine();
  const wrongPackage = {
    address: 'mallory.veilproof.testnet',
    dataHash: g.snapshot.dataHash,
    reportId: g.report.reportId,
    snapshot: g.snapshot,
  };
  const result = verifyReport({
    report: g.report,
    onchainRecord: g.onchainRecord,
    disclosurePackage: wrongPackage,
    policy: g.policy,
    nowNs: g.nowNs,
  });
  assert.equal(result.valid, false);
  assert.equal(checkByName(result, 'prover_binding').passed, false);
  assert.match(checkByName(result, 'prover_binding').detail, /does not hash to the report prover/);
  for (const name of ['report_hash', 'evidence_hash', 'policy_hash', 'data_hash', 'claims', 'validity']) {
    assert.equal(checkByName(result, name).passed, true, `${name} should still pass`);
  }
});

test('verify expired: report expiry fails validity, registry alone is not enough', () => {
  const g = genuine();
  const expired = JSON.parse(JSON.stringify(g.report));
  expired.expiresAt = (NOW_NS - 1n * DAY_NS).toString();
  const result = verifyReport({
    report: expired,
    onchainRecord: onchainRecordFor(expired, { valid: true }),
    disclosurePackage: g.disclosurePackage,
    policy: g.policy,
    nowNs: g.nowNs,
  });
  assert.equal(result.valid, false);
  assert.equal(checkByName(result, 'validity').passed, false);
  assert.match(checkByName(result, 'validity').detail, /expired/);
  for (const name of CHECK_ORDER.filter((n) => n !== 'validity')) {
    assert.equal(checkByName(result, name).passed, true, `${name} should still pass`);
  }
});

test('verify revoked: registry valid=false fails validity with the reason', () => {
  const g = genuine();
  const result = verifyReport({
    report: g.report,
    onchainRecord: onchainRecordFor(g.report, { valid: false }),
    disclosurePackage: g.disclosurePackage,
    policy: g.policy,
    nowNs: g.nowNs,
  });
  assert.equal(result.valid, false);
  assert.equal(checkByName(result, 'validity').passed, false);
  assert.match(checkByName(result, 'validity').detail, /Registry reports the claim invalid/);
  for (const name of CHECK_ORDER.filter((n) => n !== 'validity')) {
    assert.equal(checkByName(result, name).passed, true, `${name} should still pass`);
  }
});

test('verify claims mismatch: verifying 60 days later moves the window', () => {
  const g = genuine();
  const later = NOW_NS + 60n * DAY_NS;
  const result = verifyReport({
    report: g.report,
    onchainRecord: g.onchainRecord,
    disclosurePackage: g.disclosurePackage,
    policy: g.policy,
    nowNs: later,
  });
  assert.equal(result.valid, false);
  // The report itself is untouched, so the hash checks still pass.
  for (const name of ['report_hash', 'evidence_hash', 'policy_hash', 'data_hash']) {
    assert.equal(checkByName(result, name).passed, true, `${name} should still pass`);
  }
  assert.equal(checkByName(result, 'claims').passed, false);
  assert.match(checkByName(result, 'claims').detail, /tx_count_in_window/);
});

test('verify throws only on malformed input', () => {
  const g = genuine();
  const args = {
    report: g.report,
    onchainRecord: g.onchainRecord,
    disclosurePackage: g.disclosurePackage,
    policy: g.policy,
    nowNs: g.nowNs,
  };
  assert.throws(() => verifyReport({ ...args, report: null }), /report must be an object/);
  assert.throws(() => verifyReport({ ...args, onchainRecord: null }), /onchainRecord must be an object/);
  assert.throws(() => verifyReport({ ...args, disclosurePackage: { address: ADDRESS } }), /snapshot must be an object/);
  assert.throws(() => verifyReport({ ...args, policy: null }), /policy must be an object/);
  assert.throws(() => verifyReport({ ...args, nowNs: undefined }), /nowNs must be a nanosecond epoch/);
  assert.throws(() => verifyReport({ ...args, nowNs: 'not-a-number' }), /nowNs must be a nanosecond epoch/);
});

test('verify null AI summary is allowed and never auto-filled', () => {
  const g = genuine();
  assert.equal(g.report.aiSummary, null);
  const result = verifyReport({
    report: g.report,
    onchainRecord: g.onchainRecord,
    disclosurePackage: g.disclosurePackage,
    policy: g.policy,
    nowNs: g.nowNs,
  });
  assert.equal(result.valid, true);
  assert.equal(JSON.stringify(result).includes('analys'), false);
});

// --- Parity: the browser copy in public/verify.html must agree ---
// The page inlines the verify logic (it cannot import ../src/ because
// Vercel serves only public/). This test extracts that inline script,
// runs it in a VM with Web Crypto, and asserts the same verdicts as
// the Node module on the same fixtures. If the two drift, this fails.
function loadPageVerify() {
  const html = readFileSync(new URL('../public/verify.html', import.meta.url), 'utf8');
  const match = html.match(/<script>([\s\S]*?)<\/script>/);
  assert.ok(match, 'verify.html must contain one inline <script> block');
  const sandbox = {
    window: {},
    crypto: globalThis.crypto,
    // The page runs in a browser where these are globals; a vm context
    // only has the JS intrinsics, so provide them explicitly.
    TextEncoder: globalThis.TextEncoder,
    TextDecoder: globalThis.TextDecoder,
    atob: globalThis.atob,
    btoa: globalThis.btoa,
    console,
  };
  vm.createContext(sandbox);
  // In a browser self === window === the global object; mirror that
  // so the UMD build of tweetnacl (which writes to self.nacl) lands
  // on the vm global, where globalThis.nacl finds it.
  sandbox.self = sandbox;
  // Load the vendored tweetnacl INSIDE the vm realm, exactly as the
  // browser loads nacl.min.js via a <script> tag: tweetnacl checks
  // `instanceof Uint8Array`, which fails across realms, so the page
  // and nacl must share one realm (in production they always do).
  vm.runInContext(readFileSync(new URL('../public/js/nacl.min.js', import.meta.url), 'utf8'), sandbox);
  vm.runInContext(match[1], sandbox);
  assert.ok(sandbox.window.VeilProofVerify, 'page script must expose window.VeilProofVerify');
  return sandbox.window.VeilProofVerify;
}

test('parity: page copy agrees with the Node module', async () => {
  const page = loadPageVerify();
  const g = genuine();
  const base = {
    report: g.report,
    onchainRecord: g.onchainRecord,
    disclosurePackage: g.disclosurePackage,
    policy: g.policy,
    nowNs: g.nowNs,
  };
  const cases = {};
  cases.happy = base;
  const tampered = JSON.parse(JSON.stringify(g.report));
  tampered.claims[0].value = '1';
  cases.tampered = { ...base, report: tampered };
  cases.wrongAddress = {
    ...base,
    disclosurePackage: { ...g.disclosurePackage, address: 'mallory.veilproof.testnet' },
  };
  const expired = JSON.parse(JSON.stringify(g.report));
  expired.expiresAt = (NOW_NS - 1n * DAY_NS).toString();
  cases.expired = { ...base, report: expired, onchainRecord: onchainRecordFor(expired, { valid: true }) };
  cases.timeShift = { ...base, nowNs: NOW_NS + 60n * DAY_NS };
  // Malformed snapshot: the claims re-run throws, and the detail must
  // carry the engine's exact message in both implementations.
  const badSnap = JSON.parse(JSON.stringify(g.snapshot));
  badSnap.account.amount = '-5';
  badSnap.dataHash = computeDataHash(badSnap.account.accountId, badSnap.account.amount, badSnap.account.locked, badSnap.txs);
  const badReport = JSON.parse(JSON.stringify(g.report));
  badReport.evidenceRefs.dataHash = badSnap.dataHash;
  cases.badSnapshot = {
    ...base,
    report: badReport,
    onchainRecord: onchainRecordFor(badReport),
    disclosurePackage: buildDisclosurePackage(badReport, ADDRESS, badSnap),
  };

  for (const [name, args] of Object.entries(cases)) {
    const nodeResult = verifyReport(args);
    const pageResult = await page.verifyReport(args);
    // The page result is built inside the vm realm, so its objects
    // carry a different prototype and deepStrictEqual would fail on
    // that alone. Compare the serialised form: content is what matters.
    assert.equal(
      JSON.stringify(pageResult),
      JSON.stringify(nodeResult),
      `page and Node disagree on ${name}`,
    );
  }
});

test('parity: page copy agrees with the Node module on a signature link', async () => {
  const page = loadPageVerify();
  const primary = snapshot();
  const linkedSnap = {
    account: { accountId: 'bob.veilproof.testnet', amount: '3000000000000000000000000', locked: '0', storage_usage: 1000, blockHeight: 100 },
    txs: [],
    blockHeight: 100,
    dataHash: computeDataHash('bob.veilproof.testnet', '3000000000000000000000000', '0', []),
  };
  const dataHash = dataHashForSnapshots([primary, linkedSnap]);
  const bundle = { wallets: [primary, linkedSnap] };
  const policy = { ...POLICY, aggregateBalanceAtLeastYocto: '8000000000000000000000000' };
  const { claims } = evaluateClaims(bundle, policy, NOW_NS);
  const report = buildReport({
    proverAddressHash: sha256Hex(ADDRESS),
    claims,
    policyVersion: POLICY_VERSION,
    aiSummary: null,
    evidenceRefs: { dataHash, attestationRef: null },
    expiresAt: EXPIRES_AT,
    linkedProverHashes: [sha256Hex('bob.veilproof.testnet')],
  });
  const record = {
    report_hash: reportHash(report),
    evidence_hash: evidenceHash(report.evidenceRefs),
    policy_hash: policyHash(POLICY_VERSION, policy),
    valid: true,
  };
  const keyPair = nacl.sign.keyPair();
  const nonceB64 = Buffer.from(new Uint8Array(32)).toString('base64');
  const sig = signLinkMessage(keyPair.secretKey, 'bob.veilproof.testnet', ADDRESS, nonceB64);
  const disclosure = buildMultiDisclosurePackage(report, ADDRESS, primary, [
    { address: 'bob.veilproof.testnet', snapshot: linkedSnap, linkSignature: sig },
  ]);
  const bindings = { 'bob.veilproof.testnet': sig.publicKey };
  const args = { report, onchainRecord: record, disclosurePackage: disclosure, policy, nowNs: NOW_NS, linkKeyBindings: bindings };
  const nodeResult = verifyReport(args);
  const pageResult = await page.verifyReport(args);
  assert.equal(JSON.stringify(pageResult), JSON.stringify(nodeResult), 'page and Node disagree on a signature link');
  assert.equal(nodeResult.valid, true);
  // And without the binding both agree it fails.
  const noBindingArgs = { ...args, linkKeyBindings: undefined };
  const nodeBad = verifyReport(noBindingArgs);
  const pageBad = await page.verifyReport(noBindingArgs);
  assert.equal(JSON.stringify(pageBad), JSON.stringify(nodeBad), 'page and Node disagree on a missing binding');
  assert.equal(nodeBad.valid, false);
});

test('verify score: a scored report recomputes exactly; a tampered score fails', () => {
  const { report, onchainRecord, disclosurePackage, policy, nowNs } = genuine();
  const snap = disclosurePackage.snapshot;
  const score = computeScore(snap, { txWindowDays: 30, volumeWindowDays: 30, noFailedWindowDays: 30 }, nowNs);
  const scored = buildReport({
    proverAddressHash: report.prover,
    claims: report.claims,
    policyVersion: POLICY_VERSION,
    aiSummary: null,
    evidenceRefs: report.evidenceRefs,
    expiresAt: EXPIRES_AT,
    score,
  });
  const record = onchainRecordFor(scored);
  const ok = verifyReport({ report: scored, onchainRecord: record, disclosurePackage, policy, nowNs });
  assert.equal(ok.valid, true);
  assert.equal(checkByName(ok, 'score').passed, true);
  // Tamper with the reported score value (and re-sign the report hash so only the score check can fail).
  const tampered = { ...scored, score: { ...score, value: score.value + 1 } };
  const tamperedRecord = onchainRecordFor(tampered);
  const bad = verifyReport({ report: tampered, onchainRecord: tamperedRecord, disclosurePackage, policy, nowNs });
  assert.equal(bad.valid, false);
  assert.equal(checkByName(bad, 'score').passed, false);
  assert.equal(checkByName(bad, 'report_hash').passed, true);
  // A v1-scored report recomputes under v1 (and must NOT be
  // recomputed under v2 — the version field picks the rules).
  const scoreV1 = computeScore(snap, { txWindowDays: 30, volumeWindowDays: 30, noFailedWindowDays: 30 }, nowNs, 'score-v1');
  const scoredV1 = buildReport({
    proverAddressHash: report.prover,
    claims: report.claims,
    policyVersion: POLICY_VERSION,
    aiSummary: null,
    evidenceRefs: report.evidenceRefs,
    expiresAt: EXPIRES_AT,
    score: scoreV1,
  });
  const recordV1 = onchainRecordFor(scoredV1);
  const okV1 = verifyReport({ report: scoredV1, onchainRecord: recordV1, disclosurePackage, policy, nowNs });
  assert.equal(okV1.valid, true);
  assert.equal(checkByName(okV1, 'score').passed, true);
  assert.equal(checkByName(okV1, 'score').detail, `Score recomputed exactly: ${scoreV1.value} (${scoreV1.band}).`);
});

test('verify multi-wallet: aggregate claims + link proofs verify; a fake link fails', () => {
  const primary = snapshot();
  const linkTx = tx({ hash: 'L'.repeat(43), senderId: 'bob.veilproof.testnet', receiverId: ADDRESS, amountYocto: '10000000000000000000000' });
  const linkedSnap = {
    account: { accountId: 'bob.veilproof.testnet', amount: '3000000000000000000000000', locked: '0', storage_usage: 1000, blockHeight: 100 },
    txs: [linkTx],
    blockHeight: 100,
    dataHash: computeDataHash('bob.veilproof.testnet', '3000000000000000000000000', '0', [linkTx]),
  };
  const dataHash = dataHashForSnapshots([primary, linkedSnap]);
  const bundle = { wallets: [primary, linkedSnap] };
  const policy = { ...POLICY, aggregateBalanceAtLeastYocto: '8000000000000000000000000' };
  const { claims } = evaluateClaims(bundle, policy, NOW_NS);
  const report = buildReport({
    proverAddressHash: sha256Hex(ADDRESS),
    claims,
    policyVersion: POLICY_VERSION,
    aiSummary: null,
    evidenceRefs: { dataHash, attestationRef: null },
    expiresAt: EXPIRES_AT,
    linkedProverHashes: [sha256Hex('bob.veilproof.testnet')],
  });
  const record = {
    report_hash: reportHash(report),
    evidence_hash: evidenceHash(report.evidenceRefs),
    policy_hash: policyHash(POLICY_VERSION, policy),
    valid: true,
  };
  const disclosure = buildMultiDisclosurePackage(report, ADDRESS, primary, [
    { address: 'bob.veilproof.testnet', snapshot: linkedSnap, linkTxHash: 'L'.repeat(43) },
  ]);
  const ok = verifyReport({ report, onchainRecord: record, disclosurePackage: disclosure, policy, nowNs: NOW_NS });
  assert.equal(ok.valid, true);
  assert.equal(checkByName(ok, 'link_proofs').passed, true);
  assert.equal(checkByName(ok, 'data_hash').passed, true);
  // A disclosure whose link tx points at someone else fails link_proofs only.
  const wrongLink = { ...disclosure, linked: [{ address: 'bob.veilproof.testnet', linkTxHash: 'A'.repeat(43), snapshot: linkedSnap }] };
  const bad = verifyReport({ report, onchainRecord: record, disclosurePackage: wrongLink, policy, nowNs: NOW_NS });
  assert.equal(bad.valid, false);
  assert.equal(checkByName(bad, 'link_proofs').passed, false);
});

test('verify multi-wallet: signature link verifies with a key binding; no binding or bad signature fails', () => {
  const primary = snapshot();
  const linkedSnap = {
    account: { accountId: 'bob.veilproof.testnet', amount: '3000000000000000000000000', locked: '0', storage_usage: 1000, blockHeight: 100 },
    txs: [],
    blockHeight: 100,
    dataHash: computeDataHash('bob.veilproof.testnet', '3000000000000000000000000', '0', []),
  };
  const dataHash = dataHashForSnapshots([primary, linkedSnap]);
  const bundle = { wallets: [primary, linkedSnap] };
  const policy = { ...POLICY, aggregateBalanceAtLeastYocto: '8000000000000000000000000' };
  const { claims } = evaluateClaims(bundle, policy, NOW_NS);
  const report = buildReport({
    proverAddressHash: sha256Hex(ADDRESS),
    claims,
    policyVersion: POLICY_VERSION,
    aiSummary: null,
    evidenceRefs: { dataHash, attestationRef: null },
    expiresAt: EXPIRES_AT,
    linkedProverHashes: [sha256Hex('bob.veilproof.testnet')],
  });
  const record = {
    report_hash: reportHash(report),
    evidence_hash: evidenceHash(report.evidenceRefs),
    policy_hash: policyHash(POLICY_VERSION, policy),
    valid: true,
  };
  const keyPair = nacl.sign.keyPair();
  const nonceB64 = Buffer.from(new Uint8Array(32)).toString('base64');
  const sig = signLinkMessage(keyPair.secretKey, 'bob.veilproof.testnet', ADDRESS, nonceB64);
  const bindings = { 'bob.veilproof.testnet': sig.publicKey };
  const disclosure = buildMultiDisclosurePackage(report, ADDRESS, primary, [
    { address: 'bob.veilproof.testnet', snapshot: linkedSnap, linkSignature: sig },
  ]);
  const args = { report, onchainRecord: record, disclosurePackage: disclosure, policy, nowNs: NOW_NS, linkKeyBindings: bindings };
  const ok = verifyReport(args);
  assert.equal(ok.valid, true);
  assert.equal(checkByName(ok, 'link_proofs').passed, true);
  assert.match(checkByName(ok, 'link_proofs').detail, /by signature/);
  // No key binding: the verifier must not trust the key in the
  // disclosure package alone, so link_proofs fails and only it fails.
  const noBinding = verifyReport({ ...args, linkKeyBindings: undefined });
  assert.equal(noBinding.valid, false);
  assert.equal(checkByName(noBinding, 'link_proofs').passed, false);
  assert.equal(checkByName(noBinding, 'data_hash').passed, true);
  // A binding for a DIFFERENT key fails the same way.
  const otherKey = nacl.sign.keyPair();
  const wrongBinding = verifyReport({
    ...args,
    linkKeyBindings: { 'bob.veilproof.testnet': `ed25519:${base58Encode(otherKey.publicKey)}` },
  });
  assert.equal(checkByName(wrongBinding, 'link_proofs').passed, false);
  // A signature for a different pairing is rejected at build time.
  const wrongPairSig = signLinkMessage(keyPair.secretKey, 'bob.veilproof.testnet', 'mallory.veilproof.testnet', nonceB64);
  assert.throws(
    () => buildMultiDisclosurePackage(report, ADDRESS, primary, [{ address: 'bob.veilproof.testnet', snapshot: linkedSnap, linkSignature: wrongPairSig }]),
    /link statement for this pairing/,
  );
  // A message tampered after signing is rejected the same way (the
  // message must be the link statement for this pairing).
  const tamperedMsg = { ...sig, message: buildLinkMessage('bob.veilproof.testnet', ADDRESS) + '!' };
  assert.throws(
    () => buildMultiDisclosurePackage(report, ADDRESS, primary, [{ address: 'bob.veilproof.testnet', snapshot: linkedSnap, linkSignature: tamperedMsg }]),
    /link statement for this pairing/,
  );
  // A signature swapped for another key's is rejected cryptographically.
  const otherSig = signLinkMessage(otherKey.secretKey, 'bob.veilproof.testnet', ADDRESS, nonceB64);
  assert.throws(
    () => buildMultiDisclosurePackage(report, ADDRESS, primary, [{ address: 'bob.veilproof.testnet', snapshot: linkedSnap, linkSignature: { ...sig, signature: otherSig.signature } }]),
    /does not verify/,
  );
  // Both proofs at once is a caller error.
  assert.throws(
    () => buildMultiDisclosurePackage(report, ADDRESS, primary, [{ address: 'bob.veilproof.testnet', snapshot: linkedSnap, linkTxHash: 'L'.repeat(43), linkSignature: sig }]),
    /exactly one of/,
  );
});

test('verify old reports: no score and no linked wallets still verify', () => {
  const { report, onchainRecord, disclosurePackage, policy, nowNs } = genuine();
  assert.equal(report.score, null);
  assert.deepEqual(report.linkedProvers, []);
  const result = verifyReport({ report, onchainRecord, disclosurePackage, policy, nowNs });
  assert.equal(result.valid, true);
  assert.equal(checkByName(result, 'score').passed, true);
  assert.equal(checkByName(result, 'link_proofs').passed, true);
});
