// Parity: public/js/verify-browser.js (the module the homepage live
// demo uses) must agree with src/verify-report.js on the same
// fixtures. The verifier portal keeps its own inlined copy, covered
// by the parity test in test/verify-report.test.mjs — all three copies
// must stay in sync, and these two tests catch drift.

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { evaluateClaims } from '../src/claims-engine.js';
import { computeDataHash } from '../src/onchain.js';
import { buildReport, reportHash, evidenceHash, policyHash } from '../src/report.js';
import { buildDisclosurePackage, buildMultiDisclosurePackage } from '../src/disclosure.js';
import { verifyReport as nodeVerifyReport } from '../src/verify-report.js';
import { verifyReport as browserVerifyReport } from '../public/js/verify-browser.js';
import { buildMultiDisclosurePackage as browserBuildMultiDisclosurePackage } from '../public/js/disclosure.js';
import { signLinkMessage } from '../src/nep413.js';
import nacl from 'tweetnacl';

globalThis.nacl = nacl;

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

function snapshot() {
  const snap = {
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
    report,
    onchainRecord: onchainRecordFor(report),
    disclosurePackage: buildDisclosurePackage(report, ADDRESS, snap),
    policy: POLICY,
    nowNs: NOW_NS,
  };
}

test('browser verify module agrees with the Node module on every fixture', async () => {
  const g = genuine();
  const base = {
    report: g.report,
    onchainRecord: g.onchainRecord,
    disclosurePackage: g.disclosurePackage,
    policy: g.policy,
    nowNs: g.nowNs,
  };
  const cases = { happy: base };
  // P2: a salted report must verify identically on both paths, and a
  // wrong salt must fail identically on both paths.
  const salt = (await import('../src/report.js')).newProverSalt();
  const saltedHash = (await import('../src/report.js')).saltedAddressHash(salt, ADDRESS);
  const saltedSnap = snapshot();
  const saltedReport = buildReport({
    proverAddressHash: saltedHash,
    claims: evaluateClaims(saltedSnap, POLICY, NOW_NS).claims,
    policyVersion: POLICY_VERSION,
    aiSummary: null,
    evidenceRefs: { dataHash: saltedSnap.dataHash, attestationRef: null },
    expiresAt: EXPIRES_AT,
  });
  const saltedBase = {
    report: saltedReport,
    onchainRecord: onchainRecordFor(saltedReport),
    disclosurePackage: buildDisclosurePackage(saltedReport, ADDRESS, saltedSnap, salt),
    policy: POLICY,
    nowNs: NOW_NS,
  };
  cases.salted = saltedBase;
  cases.saltedWrongSalt = {
    ...saltedBase,
    disclosurePackage: { ...saltedBase.disclosurePackage, salt: (await import('../src/report.js')).newProverSalt() },
  };
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
  const badSnap = JSON.parse(JSON.stringify(snapshot()));
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
    const nodeResult = nodeVerifyReport(args);
    const browserResult = await browserVerifyReport(args);
    assert.equal(
      JSON.stringify(browserResult),
      JSON.stringify(nodeResult),
      `browser module and Node disagree on ${name}`,
    );
  }
  assert.equal(nodeVerifyReport(base).valid, true);
  assert.equal(nodeVerifyReport(saltedBase).valid, true);
  assert.equal(nodeVerifyReport(cases.saltedWrongSalt).valid, false);
});

test('browser verify module throws on malformed input, like the Node module', async () => {
  const g = genuine();
  const base = {
    report: g.report,
    onchainRecord: g.onchainRecord,
    disclosurePackage: g.disclosurePackage,
    policy: g.policy,
    nowNs: g.nowNs,
  };
  await assert.rejects(() => browserVerifyReport({ ...base, report: null }), /report must be an object/);
  await assert.rejects(() => browserVerifyReport({ ...base, policy: null }), /policy must be an object/);
  await assert.rejects(() => browserVerifyReport({ ...base, nowNs: 'not-a-number' }), /nowNs must be a nanosecond epoch/);
});

test('browser verify module agrees with the Node module on a signature link', async () => {
  const primary = snapshot();
  const linkedSnap = {
    account: { accountId: 'bob.veilproof.testnet', amount: '3000000000000000000000000', locked: '0', storage_usage: 1000, blockHeight: 100 },
    txs: [],
    blockHeight: 100,
    dataHash: computeDataHash('bob.veilproof.testnet', '3000000000000000000000000', '0', []),
  };
  const { dataHashForSnapshots } = await import('../src/onchain.js');
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
  // The browser disclosure builder must accept the signature link too.
  const browserDisclosure = await browserBuildMultiDisclosurePackage(report, ADDRESS, primary, [
    { address: 'bob.veilproof.testnet', snapshot: linkedSnap, linkSignature: sig },
  ]);
  const nodeDisclosure = buildMultiDisclosurePackage(report, ADDRESS, primary, [
    { address: 'bob.veilproof.testnet', snapshot: linkedSnap, linkSignature: sig },
  ]);
  assert.deepEqual(browserDisclosure, nodeDisclosure);
  const args = { report, onchainRecord: record, disclosurePackage: browserDisclosure, policy, nowNs: NOW_NS, linkKeyBindings: bindings };
  const nodeResult = nodeVerifyReport(args);
  const browserResult = await browserVerifyReport(args);
  assert.equal(JSON.stringify(browserResult), JSON.stringify(nodeResult), 'browser module and Node disagree on a signature link');
  assert.equal(nodeResult.valid, true);
});
