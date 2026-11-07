// VeilProof NEAR AI attestation verification tests.
//
// These tests execute against the ACTUAL verification code in
// src/attestation-verify.js. Only the Intel DCAP chain itself is
// stubbed (the fixture builder stands in for collateral fetch +
// quote verification with the TD values @phala/dcap-qvl returned for
// the real fixture quotes); every other check — nonce binding, signer
// binding, echoed fields, RTMR3 replay, MRCONFIGID, model identity,
// measurements, response-signature recovery and byte binding — runs
// for real against real NEAR AI Cloud evidence (the fixture in
// test/fixtures/near-ai-attestation.json).
//
// No test asserts VERIFIED on a stubbed verifier: the happy-path
// tests build a coherent fixture and run the full pipeline, and the
// live test (test/attestation-live.test.mjs, opt-in) runs the real
// DCAP chain against the live API.
//
// No network, no key, except the live test file.

import test from 'node:test';
import assert from 'node:assert/strict';
import nacl from 'tweetnacl';
import {
  verifyAttestationReport,
  verifyAttestationEvidence,
  verifyResponseSignature,
  combineAttestation,
  attestationStatusAt,
  replayRtmr3,
  checkMrConfigId,
  decodeSigningIdentity,
  recoverEcdsaAddress,
  verifyEd25519Signature,
  expectedSignatureText,
  resolveAttestationPolicy,
  createNonceStore,
  verifyQuoteDcap,
  sha256Hex,
  DEFAULT_TCB_ACCEPTED,
  DEFAULT_MAX_EVIDENCE_AGE_MS,
  DEFAULT_PCCS_URL,
} from '../src/attestation-verify.js';
import { buildAttestationFixture, loadAttestationFixture, signText, signEcdsaText } from './attestation-fixture.mjs';

const MODEL = 'z-ai/glm-5.3-flash';
const policy = resolveAttestationPolicy({});

function policyWith(overrides) {
  return { ...policy, ...overrides };
}

// --- Pure helpers -------------------------------------------------------

test('RTMR3 replay: live gateway event log (JSON string) replays to the quote RTMR3', () => {
  const raw = loadAttestationFixture();
  const replay = replayRtmr3(raw.gateway.report.event_log);
  assert.equal(replay.rtmr3, raw.gateway.verified.rtMr3);
  assert.equal(replay.checked, 10);
  assert.equal(replay.total, 30);
  assert.equal(replay.composeHash, raw.gateway.report.info.tcb_info.compose_hash);
  assert.ok(replay.appId);
  assert.ok(replay.instanceId);
});

test('RTMR3 replay: live model event log (already an array) replays to the quote RTMR3', () => {
  const raw = loadAttestationFixture();
  const replay = replayRtmr3(raw.modelReport.report.event_log);
  assert.equal(replay.rtmr3, raw.modelReport.verified.rtMr3);
  assert.equal(replay.checked, 15);
  assert.equal(replay.total, 35);
  assert.equal(replay.composeHash, raw.modelReport.report.info.tcb_info.compose_hash);
});

test('RTMR3 replay: a tampered event payload changes the replayed RTMR3, and a stated digest mismatch throws', () => {
  const raw = loadAttestationFixture();
  const events = JSON.parse(raw.gateway.report.event_log);
  const composeEvent = events.find((e) => e.imr === 3 && e.event === 'compose-hash');
  composeEvent.event_payload = '00'.repeat(32);
  // The imr=3 events carry an empty digest, so a tampered payload does
  // not throw here — it replays to a DIFFERENT RTMR3, which the quote
  // comparison in verifyAttestationReport then rejects.
  const replay = replayRtmr3(JSON.stringify(events));
  assert.notEqual(replay.rtmr3, raw.gateway.verified.rtMr3);
  // An event that DOES state a digest must match the recomputed one.
  const events2 = JSON.parse(raw.gateway.report.event_log);
  const appIdEvent = events2.find((e) => e.imr === 3 && e.event === 'app-id');
  appIdEvent.digest = 'ff'.repeat(48);
  assert.throws(() => replayRtmr3(JSON.stringify(events2)), /does not match the recomputed digest/);
});

test('MRCONFIGID: live app_compose matches the quote, a tampered one does not', () => {
  const raw = loadAttestationFixture();
  const mrConfigId = Buffer.from(raw.gateway.verified.mrConfigId, 'hex');
  assert.equal(checkMrConfigId(mrConfigId, raw.gateway.report.info.tcb_info.app_compose), true);
  assert.equal(checkMrConfigId(mrConfigId, raw.gateway.report.info.tcb_info.app_compose + ' '), false);
  assert.equal(checkMrConfigId(mrConfigId, 'not the compose'), false);
});

test('decodeSigningIdentity: ecdsa is 20 bytes, ed25519 is 32, anything else throws', () => {
  assert.equal(decodeSigningIdentity('0xb98a789cdc4817275f5155593ba73ef2a957e779', 'ecdsa').length, 20);
  assert.equal(decodeSigningIdentity('a'.repeat(64), 'ed25519').length, 32);
  assert.throws(() => decodeSigningIdentity('0x1234', 'ecdsa'), /20 bytes/);
  assert.throws(() => decodeSigningIdentity('a'.repeat(64), 'ecdsa'), /20 bytes/);
  assert.throws(() => decodeSigningIdentity('0x' + 'a'.repeat(40), 'rsa'), /unsupported signing_algo/);
});

test('recoverEcdsaAddress: round-trips an EIP-191 signature to the signing key address', () => {
  const privateKey = new Uint8Array(32).fill(0x22);
  const text = `${MODEL}:aaa:bbb`;
  const signature = signEcdsaText(text, privateKey);
  const recovered = recoverEcdsaAddress(text, signature);
  assert.match(recovered, /^0x[0-9a-f]{40}$/);
  // A different text must not recover the same address from this sig.
  const other = recoverEcdsaAddress(`${MODEL}:aaa:ccc`, signature);
  assert.notEqual(other, recovered);
  assert.throws(() => recoverEcdsaAddress(text, 'deadbeef'), /65 bytes/);
  assert.throws(() => recoverEcdsaAddress(text, `${signature.slice(0, -2)}29`), /recovery byte/);
});

test('verifyEd25519Signature: verifies a real detached signature and rejects a wrong one', () => {
  const pair = nacl.sign.keyPair();
  const text = 'hello ed25519';
  const sig = Buffer.from(nacl.sign.detached(Buffer.from(text, 'utf8'), pair.secretKey)).toString('hex');
  const pub = Buffer.from(pair.publicKey).toString('hex');
  assert.equal(verifyEd25519Signature(text, sig, pub), true);
  assert.equal(verifyEd25519Signature('hello ed25519!', sig, pub), false);
  assert.equal(verifyEd25519Signature(text, sig, Buffer.from(nacl.sign.keyPair().publicKey).toString('hex')), false);
});

test('expectedSignatureText: provider_tee carries the model id, gateway does not', () => {
  assert.equal(expectedSignatureText('provider_tee', MODEL, 'aa', 'bb'), `${MODEL}:aa:bb`);
  assert.equal(expectedSignatureText('gateway', MODEL, 'aa', 'bb'), 'aa:bb');
  assert.throws(() => expectedSignatureText('weird', MODEL, 'aa', 'bb'), /unknown signature kind/);
});

test('resolveAttestationPolicy: defaults match the official SDK policy; env overrides apply', () => {
  assert.deepEqual(policy.tcbAccepted, DEFAULT_TCB_ACCEPTED);
  assert.equal(policy.maxEvidenceAgeMs, DEFAULT_MAX_EVIDENCE_AGE_MS);
  assert.equal(policy.requireModel, true);
  assert.equal(policy.requireSignature, true);
  assert.equal(policy.requireGpu, false);
  assert.equal(policy.measurements, null);
  assert.equal(policy.pccsUrl, DEFAULT_PCCS_URL);
  assert.equal(DEFAULT_PCCS_URL, 'https://pccs.phala.network/sgx/certification/v4/');
  const custom = resolveAttestationPolicy({
    VEILPROOF_ATTESTATION_TCB_ACCEPT: 'UpToDate',
    VEILPROOF_ATTESTATION_MAX_AGE_MS: '60000',
    VEILPROOF_ATTESTATION_REQUIRE_MODEL: 'false',
  });
  assert.deepEqual(custom.tcbAccepted, ['UpToDate']);
  assert.equal(custom.maxEvidenceAgeMs, 60000);
  assert.equal(custom.requireModel, false);
  assert.throws(
    () => resolveAttestationPolicy({ VEILPROOF_ATTESTATION_MEASUREMENTS: 'not json' }),
    /VEILPROOF_ATTESTATION_MEASUREMENTS is invalid/,
  );
});

test('verifyQuoteDcap: no pccsUrl falls back to the default Phala PCCS URL (never undefined)', async () => {
  // Regression: passing undefined as the PCCS URL made @phala/dcap-qvl throw
  // "Cannot read properties of undefined (reading 'replace')" and every live
  // attestation came back UNVERIFIED on collateral. The default must be the
  // Phala v4 PCCS URL, and verifyQuoteDcap must use it when no URL is given.
  let seenUrl = 'not-called';
  const mockDcap = {
    getCollateral: async (url) => { seenUrl = url; return { fake: true }; },
    verify: () => ({ ok: true, status: 'UpToDate', advisoryIds: [] }),
  };
  const { evidence } = buildAttestationFixture();
  const quoteBytes = Buffer.from(evidence.gateway_attestation.intel_quote.replace(/^0x/, ''), 'hex');
  const result = await verifyQuoteDcap(quoteBytes, { dcap: mockDcap });
  assert.equal(seenUrl, DEFAULT_PCCS_URL);
  assert.equal(result.ok, true);
});

test('createNonceStore: a nonce is seen once, then pruned after its age', () => {
  const store = createNonceStore(1000);
  assert.equal(store.has('a'.repeat(64), 0), false);
  store.add('a'.repeat(64), 0);
  assert.equal(store.has('a'.repeat(64), 500), true);
  assert.equal(store.has('a'.repeat(64), 1001), false);
  assert.equal(store.size(1001), 0);
});

test('attestationStatusAt: VERIFIED past expiresAt is EXPIRED, everything else stands', () => {
  assert.equal(attestationStatusAt({ status: 'VERIFIED', expiresAt: new Date(1000).toISOString() }, 2000), 'EXPIRED');
  assert.equal(attestationStatusAt({ status: 'VERIFIED', expiresAt: new Date(5000).toISOString() }, 2000), 'VERIFIED');
  assert.equal(attestationStatusAt({ status: 'FAILED', expiresAt: new Date(1000).toISOString() }, 2000), 'FAILED');
  assert.equal(attestationStatusAt({ status: 'UNVERIFIED' }, 999999), 'UNVERIFIED');
  assert.equal(attestationStatusAt(null, 0), 'UNVERIFIED');
});

// --- One report ---------------------------------------------------------

test('verifyAttestationReport: live gateway report verifies, with measurements recorded', async () => {
  const { nonce, evidence, dcap } = buildAttestationFixture();
  const result = await verifyAttestationReport(evidence.gateway_attestation, {
    role: 'gateway',
    nonce,
    model: MODEL,
    policy,
    dcap,
  });
  assert.equal(result.outcome, 'verified');
  assert.equal(result.checks.nonceBound, true);
  assert.equal(result.checks.signerBound, true);
  assert.equal(result.checks.echoedNonce, true);
  assert.equal(result.checks.echoedReportData, true);
  assert.equal(result.checks.rtmr3Replayed, true);
  assert.equal(result.checks.rtmr3Events, 10);
  assert.equal(result.checks.mrConfigId, true);
  assert.equal(result.checks.measurementsChecked, true);
  assert.equal(result.checks.measurementsAllowlisted, null);
  assert.equal(result.tcbStatus, 'UpToDate');
  assert.deepEqual(result.advisoryIds, []);
  assert.equal(result.measurements.mrtd, loadAttestationFixture().gateway.verified.mrTd);
  assert.equal(result.measurements.composeHash, loadAttestationFixture().gateway.report.info.tcb_info.compose_hash);
  assert.equal(result.gpu.present, false);
});

test('verifyAttestationReport: live model report verifies, model identity checked', async () => {
  const { nonce, evidence, dcap } = buildAttestationFixture();
  const result = await verifyAttestationReport(evidence.model_attestations[0], {
    role: 'model',
    nonce,
    model: MODEL,
    policy,
    dcap,
  });
  assert.equal(result.outcome, 'verified');
  assert.equal(result.checks.modelIdentity, true);
  assert.equal(result.modelName, MODEL);
  assert.equal(result.checks.rtmr3Events, 15);
});

test('forged attestation: evidence for a different nonce FAILS (nonce not bound in the verified quote)', async () => {
  const { evidence, dcap } = buildAttestationFixture();
  const otherNonce = 'f'.repeat(64);
  const result = await verifyAttestationReport(evidence.gateway_attestation, {
    role: 'gateway',
    nonce: otherNonce,
    model: MODEL,
    policy,
    dcap,
  });
  assert.equal(result.outcome, 'failed');
  assert.equal(result.check, 'nonce-binding');
});

test('forged attestation: echoed request_nonce changed after the quote was made FAILS', async () => {
  const { nonce, evidence, dcap } = buildAttestationFixture();
  const tampered = { ...evidence.gateway_attestation, request_nonce: '0'.repeat(64) };
  const result = await verifyAttestationReport(tampered, { role: 'gateway', nonce, model: MODEL, policy, dcap });
  assert.equal(result.outcome, 'failed');
  assert.equal(result.check, 'echoed-nonce');
});

test('forged attestation: echoed report_data changed FAILS', async () => {
  const { nonce, evidence, dcap } = buildAttestationFixture();
  const tampered = { ...evidence.gateway_attestation, report_data: '00'.repeat(64) };
  const result = await verifyAttestationReport(tampered, { role: 'gateway', nonce, model: MODEL, policy, dcap });
  assert.equal(result.outcome, 'failed');
  assert.equal(result.check, 'echoed-report-data');
});

test('modified attestation: tampered event log FAILS the RTMR3 replay', async () => {
  const { nonce, evidence, dcap } = buildAttestationFixture();
  const events = JSON.parse(evidence.gateway_attestation.event_log);
  events.find((e) => e.imr === 3 && e.event === 'app-id').event_payload = '00'.repeat(20);
  const tampered = { ...evidence.gateway_attestation, event_log: JSON.stringify(events) };
  const result = await verifyAttestationReport(tampered, { role: 'gateway', nonce, model: MODEL, policy, dcap });
  assert.equal(result.outcome, 'failed');
  assert.equal(result.check, 'rtmr3-replay');
});

test('modified attestation: tampered app_compose FAILS the MRCONFIGID check', async () => {
  const { nonce, evidence, dcap } = buildAttestationFixture();
  const info = JSON.parse(JSON.stringify(evidence.gateway_attestation.info));
  info.tcb_info.app_compose += ' ';
  const tampered = { ...evidence.gateway_attestation, info };
  const result = await verifyAttestationReport(tampered, { role: 'gateway', nonce, model: MODEL, policy, dcap });
  assert.equal(result.outcome, 'failed');
  assert.equal(result.check, 'mrconfigid');
});

test('wrong model identity: model report for another model FAILS', async () => {
  const { nonce, evidence, dcap } = buildAttestationFixture({ model: 'other/model' });
  const result = await verifyAttestationReport(evidence.model_attestations[0], {
    role: 'model',
    nonce,
    model: MODEL,
    policy,
    dcap,
  });
  assert.equal(result.outcome, 'failed');
  assert.equal(result.check, 'model-identity');
});

test('TCB policy: OutOfDate is accepted by default, Revoked and SWHardeningNeeded FAIL', async () => {
  const fixture = buildAttestationFixture({ tcbStatus: 'OutOfDate', advisoryIds: ['INTEL-SA-12345'] });
  const ok = await verifyAttestationReport(fixture.evidence.gateway_attestation, {
    role: 'gateway',
    nonce: fixture.nonce,
    model: MODEL,
    policy,
    dcap: fixture.dcap,
  });
  assert.equal(ok.outcome, 'verified');
  assert.equal(ok.tcbStatus, 'OutOfDate');
  assert.deepEqual(ok.advisoryIds, ['INTEL-SA-12345']);

  const revoked = buildAttestationFixture({ tcbStatus: 'Revoked' });
  const bad = await verifyAttestationReport(revoked.evidence.gateway_attestation, {
    role: 'gateway',
    nonce: revoked.nonce,
    model: MODEL,
    policy,
    dcap: revoked.dcap,
  });
  assert.equal(bad.outcome, 'failed');
  assert.equal(bad.check, 'tcb-policy');

  const hardening = buildAttestationFixture({ tcbStatus: 'SWHardeningNeeded' });
  const bad2 = await verifyAttestationReport(hardening.evidence.gateway_attestation, {
    role: 'gateway',
    nonce: hardening.nonce,
    model: MODEL,
    policy,
    dcap: hardening.dcap,
  });
  assert.equal(bad2.outcome, 'failed');
  assert.equal(bad2.check, 'tcb-policy');
});

test('debug mode: a quote with the TDX debug bit set FAILS', async () => {
  const fixture = buildAttestationFixture();
  const dcap = {
    ...fixture.dcap,
    verify: (quoteBytes) => {
      const verified = fixture.dcap.verify(quoteBytes);
      const td = verified.report.asTd10();
      td.tdAttributes = Buffer.from('0100001000000000', 'hex');
      return verified;
    },
  };
  const result = await verifyAttestationReport(fixture.evidence.gateway_attestation, {
    role: 'gateway',
    nonce: fixture.nonce,
    model: MODEL,
    policy,
    dcap,
  });
  assert.equal(result.outcome, 'failed');
  assert.equal(result.check, 'debug-mode');
});

test('missing or malformed evidence is UNVERIFIED, never VERIFIED or FAILED', async () => {
  const { nonce, dcap } = buildAttestationFixture();
  const cases = [
    [{}, 'shape'],
    [{ intel_quote: 'zz', signing_address: '0x' + 'a'.repeat(40), signing_algo: 'ecdsa', request_nonce: nonce }, 'quote-encoding'],
    [
      { intel_quote: 'aabbcc', signing_address: '0x' + 'a'.repeat(40), signing_algo: 'ecdsa', request_nonce: nonce },
      'quote-parse',
    ],
  ];
  for (const [report, check] of cases) {
    const result = await verifyAttestationReport(report, { role: 'gateway', nonce, model: MODEL, policy, dcap });
    assert.equal(result.outcome, check === 'quote-parse' ? 'failed' : 'unverified', JSON.stringify(report).slice(0, 80));
    assert.equal(result.check, check);
  }
  const noAlgo = await verifyAttestationReport(
    { intel_quote: 'aabbcc', signing_address: '0x' + 'a'.repeat(40), request_nonce: nonce },
    { role: 'gateway', nonce, model: MODEL, policy, dcap },
  );
  assert.equal(noAlgo.outcome, 'unverified');
  assert.equal(noAlgo.check, 'shape');
});

test('measurement allowlist: matching measurements verify, unknown ones FAIL', async () => {
  const raw = loadAttestationFixture();
  const allowlist = [
    { mrtd: raw.gateway.verified.mrTd, mrconfigid: raw.gateway.verified.mrConfigId, composeHash: raw.gateway.report.info.tcb_info.compose_hash },
    { mrtd: raw.modelReport.verified.mrTd, mrconfigid: raw.modelReport.verified.mrConfigId, composeHash: raw.modelReport.report.info.tcb_info.compose_hash },
  ];
  const fixture = buildAttestationFixture();
  const ok = await verifyAttestationReport(fixture.evidence.gateway_attestation, {
    role: 'gateway',
    nonce: fixture.nonce,
    model: MODEL,
    policy: policyWith({ measurements: allowlist }),
    dcap: fixture.dcap,
  });
  assert.equal(ok.outcome, 'verified');
  assert.equal(ok.checks.measurementsAllowlisted, true);

  const wrong = await verifyAttestationReport(fixture.evidence.gateway_attestation, {
    role: 'gateway',
    nonce: fixture.nonce,
    model: MODEL,
    policy: policyWith({ measurements: [{ mrtd: '00'.repeat(48) }] }),
    dcap: fixture.dcap,
  });
  assert.equal(wrong.outcome, 'failed');
  assert.equal(wrong.check, 'measurements-allowlist');
});

test('GPU evidence: payload nonce is recorded locally, NRAS is not called, and it is not required', async () => {
  const fixture = buildAttestationFixture();
  const payload = JSON.stringify({ nonce: fixture.nonce, evidence_list: [], arch: 'H100' });
  const withGpu = { ...fixture.evidence.gateway_attestation, nvidia_payload: payload };
  const result = await verifyAttestationReport(withGpu, {
    role: 'gateway',
    nonce: fixture.nonce,
    model: MODEL,
    policy,
    dcap: fixture.dcap,
  });
  assert.equal(result.outcome, 'verified');
  assert.equal(result.gpu.present, true);
  assert.equal(result.gpu.nonceMatched, true);
  assert.equal(result.gpu.nrasVerified, false);

  const wrongNonce = { ...fixture.evidence.gateway_attestation, nvidia_payload: JSON.stringify({ nonce: '0'.repeat(64) }) };
  const result2 = await verifyAttestationReport(wrongNonce, {
    role: 'gateway',
    nonce: fixture.nonce,
    model: MODEL,
    policy,
    dcap: fixture.dcap,
  });
  assert.equal(result2.outcome, 'verified');
  assert.equal(result2.gpu.nonceMatched, false);
});

// --- Full preflight evidence --------------------------------------------

test('verifyAttestationEvidence: happy path is VERIFIED with a 60-minute expiry', async () => {
  const fixture = buildAttestationFixture();
  const nowMs = Date.now();
  const result = await verifyAttestationEvidence(fixture.evidence, {
    nonce: fixture.nonce,
    model: MODEL,
    policy,
    dcap: fixture.dcap,
    nonceStore: createNonceStore(),
    nowMs,
  });
  assert.equal(result.status, 'VERIFIED');
  assert.equal(result.method, 'near-ai-cloud-dcap');
  assert.equal(result.model, MODEL);
  assert.equal(result.nonceMatched, true);
  assert.equal(result.quoteVerified, true);
  assert.equal(result.signatureVerified, false);
  assert.equal(result.measurementsChecked, true);
  assert.equal(result.verifiedAt, new Date(nowMs).toISOString());
  assert.equal(result.expiresAt, new Date(nowMs + DEFAULT_MAX_EVIDENCE_AGE_MS).toISOString());
  assert.equal(result.details.gateway.outcome, 'verified');
  assert.equal(result.details.models.length, 1);
  assert.equal(result.details.models[0].outcome, 'verified');
  assert.equal(result.error, undefined);
});

test('replayed nonce: the same evidence verified twice FAILS the second time', async () => {
  const fixture = buildAttestationFixture();
  const store = createNonceStore();
  const first = await verifyAttestationEvidence(fixture.evidence, {
    nonce: fixture.nonce,
    model: MODEL,
    policy,
    dcap: fixture.dcap,
    nonceStore: store,
  });
  assert.equal(first.status, 'VERIFIED');
  const second = await verifyAttestationEvidence(fixture.evidence, {
    nonce: fixture.nonce,
    model: MODEL,
    policy,
    dcap: fixture.dcap,
    nonceStore: store,
  });
  assert.equal(second.status, 'FAILED');
  assert.match(second.error, /nonce already used/);
});

test('missing signing evidence: no gateway, no models, or empty models are UNVERIFIED', async () => {
  const fixture = buildAttestationFixture();
  const noGateway = await verifyAttestationEvidence(
    { model_attestations: fixture.evidence.model_attestations },
    { nonce: fixture.nonce, model: MODEL, policy, dcap: fixture.dcap, nonceStore: createNonceStore() },
  );
  assert.equal(noGateway.status, 'UNVERIFIED');
  assert.match(noGateway.error, /gateway attestation is missing/);

  const noModels = await verifyAttestationEvidence(
    { gateway_attestation: fixture.evidence.gateway_attestation },
    { nonce: fixture.nonce, model: MODEL, policy, dcap: fixture.dcap, nonceStore: createNonceStore() },
  );
  assert.equal(noModels.status, 'UNVERIFIED');
  assert.match(noModels.error, /model attestation is missing/);

  const emptyModels = await verifyAttestationEvidence(
    { gateway_attestation: fixture.evidence.gateway_attestation, model_attestations: [] },
    { nonce: fixture.nonce, model: MODEL, policy, dcap: fixture.dcap, nonceStore: createNonceStore() },
  );
  assert.equal(emptyModels.status, 'UNVERIFIED');

  const notObject = await verifyAttestationEvidence('nope', {
    nonce: fixture.nonce,
    model: MODEL,
    policy,
    dcap: fixture.dcap,
    nonceStore: createNonceStore(),
  });
  assert.equal(notObject.status, 'UNVERIFIED');
});

test('every model candidate is verified: a second, tampered candidate FAILS the evidence', async () => {
  const fixture = buildAttestationFixture();
  const tampered = JSON.parse(JSON.stringify(fixture.evidence.model_attestations[0]));
  tampered.signing_address = `0x${'1'.repeat(40)}`;
  const evidence = { ...fixture.evidence, model_attestations: [fixture.evidence.model_attestations[0], tampered] };
  const result = await verifyAttestationEvidence(evidence, {
    nonce: fixture.nonce,
    model: MODEL,
    policy,
    dcap: fixture.dcap,
    nonceStore: createNonceStore(),
  });
  assert.equal(result.status, 'FAILED');
  assert.match(result.error, /model attestation/);
  assert.equal(result.details.models.length, 2);
  assert.equal(result.details.models[0].outcome, 'verified');
  assert.equal(result.details.models[1].outcome, 'failed');
});

test('requireModel=false: gateway-only evidence verifies', async () => {
  const fixture = buildAttestationFixture();
  const result = await verifyAttestationEvidence(
    { gateway_attestation: fixture.evidence.gateway_attestation },
    { nonce: fixture.nonce, model: MODEL, policy: policyWith({ requireModel: false }), dcap: fixture.dcap, nonceStore: createNonceStore() },
  );
  assert.equal(result.status, 'VERIFIED');
  assert.deepEqual(result.details.models, []);
});

test('requireGpu=true: missing GPU evidence is UNVERIFIED', async () => {
  const fixture = buildAttestationFixture();
  const result = await verifyAttestationEvidence(fixture.evidence, {
    nonce: fixture.nonce,
    model: MODEL,
    policy: policyWith({ requireGpu: true }),
    dcap: fixture.dcap,
    nonceStore: createNonceStore(),
  });
  assert.equal(result.status, 'UNVERIFIED');
  assert.match(result.error, /GPU evidence is required/);
});

// --- Response signatures -------------------------------------------------

const REQUEST_BYTES = Buffer.from(JSON.stringify({ model: MODEL, messages: [{ role: 'user', content: 'hi' }] }), 'utf8');
const RESPONSE_BYTES = Buffer.from(
  JSON.stringify({ id: 'chatcmpl-test-1', choices: [{ message: { content: '{"verdict": "consistent", "points": []}' } }] }),
  'utf8',
);

async function verifiedPreflight(fixtureOptions = {}) {
  const fixture = buildAttestationFixture(fixtureOptions);
  const preflight = await verifyAttestationEvidence(fixture.evidence, {
    nonce: fixture.nonce,
    model: MODEL,
    policy,
    dcap: fixture.dcap,
    nonceStore: createNonceStore(),
    nonceStore: createNonceStore(),
  });
  assert.equal(preflight.status, 'VERIFIED');
  return { fixture, preflight };
}

function signatureFetch({ text, signature, kind, signingAddress, status = 200, failWith } = {}) {
  let calls = 0;
  const fetchImpl = async (url) => {
    calls += 1;
    assert.ok(String(url).includes('/v1/signature/chatcmpl-test-1'), url);
    assert.ok(String(url).includes(`model=${encodeURIComponent(MODEL)}`), url);
    assert.ok(String(url).includes('signing_algo=ecdsa') || String(url).includes('signing_algo=ed25519'), url);
    if (failWith) return failWith;
    return {
      ok: status >= 200 && status < 300,
      status,
      json: async () => ({ text, signature, signature_kind: kind, signing_address: signingAddress }),
    };
  };
  return { fetchImpl, calls: () => calls };
}

test('response signature: valid provider_tee signature over the exact bytes is VERIFIED', async () => {
  const { fixture, preflight } = await verifiedPreflight({ modelKey: true });
  const requestHash = sha256Hex(REQUEST_BYTES);
  const responseHash = sha256Hex(RESPONSE_BYTES);
  const text = expectedSignatureText('provider_tee', MODEL, requestHash, responseHash);
  const signature = signText(text, fixture.keys.model);
  const { fetchImpl } = signatureFetch({ text, signature, kind: 'provider_tee', signingAddress: fixture.keys.model.address });
  const result = await verifyResponseSignature({
    fetchImpl,
    base: 'https://cloud-api.near.ai/v1',
    completionId: 'chatcmpl-test-1',
    model: MODEL,
    signingAlgo: 'ecdsa',
    apiKey: 'sk-test',
    requestBytes: REQUEST_BYTES,
    responseBytes: RESPONSE_BYTES,
    preflight,
    policy,
  });
  assert.equal(result.status, 'VERIFIED');
  assert.equal(result.kind, 'provider_tee');
  assert.equal(result.textMatched, true);
  assert.equal(result.signerMatched, true);
  assert.equal(result.signatureVerified, true);
  assert.equal(result.signer.toLowerCase(), fixture.keys.model.address.toLowerCase());
});

test('response signature: valid gateway signature over the exact bytes is VERIFIED', async () => {
  const { fixture, preflight } = await verifiedPreflight({ gatewayKey: true });
  const text = expectedSignatureText('gateway', MODEL, sha256Hex(REQUEST_BYTES), sha256Hex(RESPONSE_BYTES));
  const signature = signText(text, fixture.keys.gateway);
  const { fetchImpl } = signatureFetch({ text, signature, kind: 'gateway', signingAddress: fixture.keys.gateway.address });
  const result = await verifyResponseSignature({
    fetchImpl,
    base: 'https://cloud-api.near.ai/v1',
    completionId: 'chatcmpl-test-1',
    model: MODEL,
    signingAlgo: 'ecdsa',
    apiKey: 'sk-test',
    requestBytes: REQUEST_BYTES,
    responseBytes: RESPONSE_BYTES,
    preflight,
    policy,
  });
  assert.equal(result.status, 'VERIFIED');
  assert.equal(result.kind, 'gateway');
  assert.equal(result.signatureVerified, true);
});

test('completion-response substitution: response bytes changed after signing FAIL the text match', async () => {
  const { fixture, preflight } = await verifiedPreflight({ modelKey: true });
  const text = expectedSignatureText('provider_tee', MODEL, sha256Hex(REQUEST_BYTES), sha256Hex(RESPONSE_BYTES));
  const signature = signText(text, fixture.keys.model);
  const { fetchImpl } = signatureFetch({ text, signature, kind: 'provider_tee', signingAddress: fixture.keys.model.address });
  const substituted = Buffer.from(RESPONSE_BYTES.toString('utf8').replace('consistent', 'inconsistent'), 'utf8');
  const result = await verifyResponseSignature({
    fetchImpl,
    base: 'https://cloud-api.near.ai/v1',
    completionId: 'chatcmpl-test-1',
    model: MODEL,
    signingAlgo: 'ecdsa',
    apiKey: 'sk-test',
    requestBytes: REQUEST_BYTES,
    responseBytes: substituted,
    preflight,
    policy,
  });
  assert.equal(result.status, 'FAILED');
  assert.match(result.error, /does not match the exact request\/response bytes/);
  assert.equal(result.textMatched, false);
});

test('invalid signature: signed by a key with no verified preflight report is UNVERIFIED', async () => {
  const { fixture, preflight } = await verifiedPreflight({ modelKey: true });
  const text = expectedSignatureText('provider_tee', MODEL, sha256Hex(REQUEST_BYTES), sha256Hex(RESPONSE_BYTES));
  const otherKey = buildAttestationFixture({ modelKey: true }).keys.model;
  const signature = signText(text, otherKey);
  const { fetchImpl } = signatureFetch({ text, signature, kind: 'provider_tee', signingAddress: otherKey.address });
  const result = await verifyResponseSignature({
    fetchImpl,
    base: 'https://cloud-api.near.ai/v1',
    completionId: 'chatcmpl-test-1',
    model: MODEL,
    signingAlgo: 'ecdsa',
    apiKey: 'sk-test',
    requestBytes: REQUEST_BYTES,
    responseBytes: RESPONSE_BYTES,
    preflight,
    policy,
  });
  assert.equal(result.status, 'UNVERIFIED');
  assert.match(result.error, /matches no verified preflight report/);
  assert.equal(result.textMatched, true);
  assert.equal(result.signatureVerified, false);
});

test('invalid signature: malformed 65-byte signature FAILS recovery', async () => {
  const { preflight } = await verifiedPreflight({ modelKey: true });
  const text = expectedSignatureText('provider_tee', MODEL, sha256Hex(REQUEST_BYTES), sha256Hex(RESPONSE_BYTES));
  const { fetchImpl } = signatureFetch({ text, signature: `${'11'.repeat(64)}29`, kind: 'provider_tee' });
  const result = await verifyResponseSignature({
    fetchImpl,
    base: 'https://cloud-api.near.ai/v1',
    completionId: 'chatcmpl-test-1',
    model: MODEL,
    signingAlgo: 'ecdsa',
    apiKey: 'sk-test',
    requestBytes: REQUEST_BYTES,
    responseBytes: RESPONSE_BYTES,
    preflight,
    policy,
  });
  assert.equal(result.status, 'FAILED');
  assert.match(result.error, /signature recovery failed/);
});

test('mismatched inference execution: a provider_tee signature from the GATEWAY key matches no model report', async () => {
  const { fixture, preflight } = await verifiedPreflight({ gatewayKey: true, modelKey: true });
  const text = expectedSignatureText('provider_tee', MODEL, sha256Hex(REQUEST_BYTES), sha256Hex(RESPONSE_BYTES));
  const signature = signText(text, fixture.keys.gateway);
  const { fetchImpl } = signatureFetch({ text, signature, kind: 'provider_tee', signingAddress: fixture.keys.gateway.address });
  const result = await verifyResponseSignature({
    fetchImpl,
    base: 'https://cloud-api.near.ai/v1',
    completionId: 'chatcmpl-test-1',
    model: MODEL,
    signingAlgo: 'ecdsa',
    apiKey: 'sk-test',
    requestBytes: REQUEST_BYTES,
    responseBytes: RESPONSE_BYTES,
    preflight,
    policy,
  });
  assert.equal(result.status, 'UNVERIFIED');
  assert.match(result.error, /matches no verified preflight report/);
});

test('wrong model identity: provider_tee text naming another model FAILS', async () => {
  const { fixture, preflight } = await verifiedPreflight({ modelKey: true });
  const text = expectedSignatureText('provider_tee', 'other/model', sha256Hex(REQUEST_BYTES), sha256Hex(RESPONSE_BYTES));
  const signature = signText(text, fixture.keys.model);
  const { fetchImpl } = signatureFetch({ text, signature, kind: 'provider_tee', signingAddress: fixture.keys.model.address });
  const result = await verifyResponseSignature({
    fetchImpl,
    base: 'https://cloud-api.near.ai/v1',
    completionId: 'chatcmpl-test-1',
    model: MODEL,
    signingAlgo: 'ecdsa',
    apiKey: 'sk-test',
    requestBytes: REQUEST_BYTES,
    responseBytes: RESPONSE_BYTES,
    preflight,
    policy,
  });
  assert.equal(result.status, 'FAILED');
  assert.match(result.error, /does not match the exact request\/response bytes/);
});

test('missing signing evidence: a 404 signature is UNVERIFIED after the bounded retries', async () => {
  const { preflight } = await verifiedPreflight({ modelKey: true });
  let calls = 0;
  const fetchImpl = async () => {
    calls += 1;
    return { ok: false, status: 404, json: async () => ({}) };
  };
  const result = await verifyResponseSignature({
    fetchImpl,
    base: 'https://cloud-api.near.ai/v1',
    completionId: 'chatcmpl-test-1',
    model: MODEL,
    signingAlgo: 'ecdsa',
    apiKey: 'sk-test',
    requestBytes: REQUEST_BYTES,
    responseBytes: RESPONSE_BYTES,
    preflight,
    policy: policyWith({ signatureRetries: 3, signatureRetryDelayMs: 1 }),
  });
  assert.equal(result.status, 'UNVERIFIED');
  assert.match(result.error, /HTTP 404 after 3 attempts/);
  assert.equal(calls, 3);
});

test('missing signing evidence: a 2xx error_code body is unavailable, not a signature', async () => {
  const { preflight } = await verifiedPreflight({ modelKey: true });
  const fetchImpl = async () => ({
    ok: true,
    status: 200,
    json: async () => ({ error_code: 'not_found', message: 'no signature recorded yet' }),
  });
  const result = await verifyResponseSignature({
    fetchImpl,
    base: 'https://cloud-api.near.ai/v1',
    completionId: 'chatcmpl-test-1',
    model: MODEL,
    signingAlgo: 'ecdsa',
    apiKey: 'sk-test',
    requestBytes: REQUEST_BYTES,
    responseBytes: RESPONSE_BYTES,
    preflight,
    policy,
  });
  assert.equal(result.status, 'UNVERIFIED');
  assert.match(result.error, /malformed/);
});

test('unknown signature_kind is UNVERIFIED: the kind is never inferred from the text shape', async () => {
  const { fixture, preflight } = await verifiedPreflight({ modelKey: true });
  const text = expectedSignatureText('provider_tee', MODEL, sha256Hex(REQUEST_BYTES), sha256Hex(RESPONSE_BYTES));
  const signature = signText(text, fixture.keys.model);
  const { fetchImpl } = signatureFetch({ text, signature, kind: undefined, signingAddress: fixture.keys.model.address });
  const result = await verifyResponseSignature({
    fetchImpl,
    base: 'https://cloud-api.near.ai/v1',
    completionId: 'chatcmpl-test-1',
    model: MODEL,
    signingAlgo: 'ecdsa',
    apiKey: 'sk-test',
    requestBytes: REQUEST_BYTES,
    responseBytes: RESPONSE_BYTES,
    preflight,
    policy,
  });
  assert.equal(result.status, 'UNVERIFIED');
  assert.match(result.error, /unknown signature_kind/);
});

test('ed25519: a valid detached signature matching the verified model report is VERIFIED', async () => {
  const { fixture, preflight } = await verifiedPreflight({ modelKey: 'ed25519' });
  const text = expectedSignatureText('provider_tee', MODEL, sha256Hex(REQUEST_BYTES), sha256Hex(RESPONSE_BYTES));
  const signature = signText(text, fixture.keys.model);
  let calls = 0;
  const fetchImpl = async (url) => {
    calls += 1;
    assert.ok(String(url).includes('signing_algo=ed25519'), url);
    return {
      ok: true,
      status: 200,
      json: async () => ({ text, signature, signature_kind: 'provider_tee', signing_address: fixture.keys.model.address }),
    };
  };
  const result = await verifyResponseSignature({
    fetchImpl,
    base: 'https://cloud-api.near.ai/v1',
    completionId: 'chatcmpl-test-1',
    model: MODEL,
    signingAlgo: 'ed25519',
    apiKey: 'sk-test',
    requestBytes: REQUEST_BYTES,
    responseBytes: RESPONSE_BYTES,
    preflight,
    policy,
  });
  assert.equal(result.status, 'VERIFIED');
  assert.equal(result.signatureVerified, true);
  assert.equal(calls, 1);
});

test('no signature fetch happens when the preflight is not VERIFIED', async () => {
  const fixture = buildAttestationFixture();
  const preflight = await verifyAttestationEvidence(
    { gateway_attestation: fixture.evidence.gateway_attestation },
    { nonce: fixture.nonce, model: MODEL, policy, dcap: fixture.dcap },
  );
  assert.equal(preflight.status, 'UNVERIFIED');
  let calls = 0;
  const fetchImpl = async () => {
    calls += 1;
    throw new Error('must not be called');
  };
  const result = await verifyResponseSignature({
    fetchImpl,
    base: 'https://cloud-api.near.ai/v1',
    completionId: 'chatcmpl-test-1',
    model: MODEL,
    signingAlgo: 'ecdsa',
    apiKey: 'sk-test',
    requestBytes: REQUEST_BYTES,
    responseBytes: RESPONSE_BYTES,
    preflight,
    policy,
  });
  assert.equal(result.status, 'UNVERIFIED');
  assert.equal(calls, 0);
});

// --- Combine -------------------------------------------------------------

test('combineAttestation: VERIFIED needs both stages; either failure stands; expiry wins', async () => {
  const { fixture, preflight } = await verifiedPreflight({ modelKey: true });
  const requestHash = sha256Hex(REQUEST_BYTES);
  const responseHash = sha256Hex(RESPONSE_BYTES);
  const text = expectedSignatureText('provider_tee', MODEL, requestHash, responseHash);
  const signature = signText(text, fixture.keys.model);
  const { fetchImpl } = signatureFetch({ text, signature, kind: 'provider_tee', signingAddress: fixture.keys.model.address });
  const sigOk = await verifyResponseSignature({
    fetchImpl,
    base: 'https://cloud-api.near.ai/v1',
    completionId: 'chatcmpl-test-1',
    model: MODEL,
    signingAlgo: 'ecdsa',
    apiKey: 'sk-test',
    requestBytes: REQUEST_BYTES,
    responseBytes: RESPONSE_BYTES,
    preflight,
    policy,
  });
  assert.equal(sigOk.status, 'VERIFIED');

  const combined = combineAttestation(preflight, sigOk, { nowMs: Date.now() });
  assert.equal(combined.status, 'VERIFIED');
  assert.equal(combined.method, 'near-ai-cloud-dcap+response-signature');
  assert.equal(combined.signatureVerified, true);
  assert.equal(combined.quoteVerified, true);

  const noSig = combineAttestation(preflight, null, { nowMs: Date.now() });
  assert.equal(noSig.status, 'UNVERIFIED');

  const sigUnverified = combineAttestation(preflight, { status: 'UNVERIFIED', signatureVerified: false, error: 'nope' }, { nowMs: Date.now() });
  assert.equal(sigUnverified.status, 'UNVERIFIED');

  const sigFailed = combineAttestation(preflight, { status: 'FAILED', signatureVerified: false, error: 'bad sig' }, { nowMs: Date.now() });
  assert.equal(sigFailed.status, 'FAILED');

  const failedPreflight = { ...preflight, status: 'FAILED', error: 'bad quote' };
  assert.equal(combineAttestation(failedPreflight, sigOk, { nowMs: Date.now() }).status, 'FAILED');

  const expired = combineAttestation(preflight, sigOk, { nowMs: Date.parse(preflight.expiresAt) + 1 });
  assert.equal(expired.status, 'EXPIRED');

  const noSigRequired = combineAttestation(preflight, null, { nowMs: Date.now(), requireSignature: false });
  assert.equal(noSigRequired.status, 'VERIFIED');
  assert.equal(noSigRequired.signatureVerified, false);
});

test('expired evidence: a VERIFIED result evaluated after its window is EXPIRED', async () => {
  const fixture = buildAttestationFixture();
  const preflight = await verifyAttestationEvidence(fixture.evidence, {
    nonce: fixture.nonce,
    model: MODEL,
    policy,
    dcap: fixture.dcap,
    nonceStore: createNonceStore(),
    nowMs: 1_000_000,
  });
  assert.equal(preflight.status, 'VERIFIED');
  assert.equal(attestationStatusAt(preflight, 1_000_000 + DEFAULT_MAX_EVIDENCE_AGE_MS + 1), 'EXPIRED');
  assert.equal(attestationStatusAt(preflight, 1_000_000), 'VERIFIED');
});
