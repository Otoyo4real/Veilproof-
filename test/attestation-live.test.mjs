// VeilProof LIVE attestation test — runs the REAL verification chain
// against the live NEAR AI Cloud API: real attestation evidence, real
// DCAP quote verification via @phala/dcap-qvl against the Phala PCCS,
// real completion, real /v1/signature check. It exercises the actual
// /api/analyze route handler (imported directly) with the real global
// fetch and the VeilProof NEAR AI key from the environment.
//
// Opt-in only: set VEILPROOF_ATTESTATION_LIVE=1 to run it. It is
// skipped by default so `npm test` stays offline and free. It spends
// one real completion (~4000 max tokens) and writes nothing onchain.
// It never prints the API key (the result carries no key).
//
// What it asserts: the full pipeline returns VERIFIED — DCAP quote
// verified, nonce + signer bound in the verified quote, RTMR3 replay
// and MRCONFIGID matched, response signature verified over the exact
// bytes and matched to the verified model report. If any live step
// fails, this test fails and the printed attestation object says
// exactly which check did not pass.

import test from 'node:test';
import assert from 'node:assert/strict';

import handler from '../api/analyze.js';

const LIVE = process.env.VEILPROOF_ATTESTATION_LIVE === '1';
const KEY_ENV = 'VEILPROOF_NEAR_AI_API_KEY';

const CLAIMS = [
  { id: 'balance_at_least', passed: true, value: '10649910726975000000000000', threshold: '5000000000000000000000000' },
  { id: 'tx_count_in_window', passed: true, value: 4, threshold: 30 },
  { id: 'volume_in_window', passed: true, value: '1850000000000000000000000', threshold: 30 },
  { id: 'no_failed_txs_in_window', passed: true, value: 0, threshold: 30 },
];
const METRICS = {
  balanceYocto: '10649910726975000000000000',
  txCount: 4,
  successTxCount: 4,
  failedTxCount: 0,
  volumeYocto: '1850000000000000000000000',
  windowDays: 30,
};

test('live: /api/analyze returns a VERIFIED attestation end to end', { skip: !LIVE }, async (t) => {
  if (!process.env[KEY_ENV]) {
    t.skip(`${KEY_ENV} is not set in this environment`);
    return;
  }
  const req = {
    method: 'POST',
    body: { claims: CLAIMS, metrics: METRICS, policyVersion: 'veilproof-policy-v1' },
  };
  const res = {
    statusCode: null,
    body: null,
    headers: {},
    setHeader(k, v) {
      this.headers[k] = v;
    },
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(obj) {
      this.body = obj;
      return this;
    },
  };
  await handler(req, res);
  assert.equal(res.statusCode, 200);
  assert.equal(res.body.status, 'ok');
  assert.ok(res.body.summary, 'summary must be present');
  assert.equal(res.body.summary.verdict, 'consistent');
  const att = res.body.summary.attestation;
  // Print the whole verdict for the run report (no key material in it).
  console.log('live attestation result:', JSON.stringify(att, null, 2));
  assert.equal(att.status, 'VERIFIED');
  assert.equal(att.verifiable, true);
  assert.equal(att.method, 'near-ai-cloud-dcap+response-signature');
  assert.equal(att.model, 'z-ai/glm-5.3-flash');
  assert.equal(att.nonceMatched, true);
  assert.equal(att.quoteVerified, true);
  assert.equal(att.signatureVerified, true);
  assert.equal(att.measurementsChecked, true);
  assert.match(att.ref, /^[0-9a-f]{64}$/);
  assert.ok(att.expiresAt && Date.parse(att.expiresAt) > Date.now(), 'expiresAt must be in the future');
  assert.equal(att.details.preflight.gateway.outcome, 'verified');
  assert.equal(att.details.preflight.models.length, 1);
  assert.equal(att.details.preflight.models[0].outcome, 'verified');
  assert.equal(att.details.signature.status, 'VERIFIED');
  assert.equal(att.details.signature.kind, 'provider_tee');
  assert.equal(att.details.signature.textMatched, true);
  assert.equal(att.details.signature.signerMatched, true);
});
