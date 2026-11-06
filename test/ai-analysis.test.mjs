// VeilProof NEAR AI analysis tests — NO network, NO key.
// All NEAR AI Cloud calls go through an injected mock fetch.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  analyseClaims,
  analyseUnderwriting,
  sanitiseClaims,
  sanitiseMetrics,
  sanitiseScore,
  checkClaimsConsistent,
  parseModelOutput,
  parseUnderwritingOutput,
  DEFAULT_MODEL,
} from '../src/ai-analysis.js';
import { buildReport } from '../src/report.js';
import { canonicalJson } from '../src/canonical.js';

// The demo wallet address and its four real demo-transfer hashes
// (demo/history.json). None of these may ever reach a request payload.
const DEMO_ADDRESS = 'veilproof-demo.testnet';
const DEMO_TX_HASHES = [
  'EQeaPK7R7nzT14a6e5kc685Yug45LDMxP4K7YhTxYn9g',
  '6xVgB3RuqhR6wHWigWoqxZVMoqQbUvvTVW19BAYL94Dj',
  'EZd6dsgPtyXJrWcdUMKtJqe611Mw3aKkAs7bqybxVMfE',
  '3Nk4rX9GURp8cK4cwShkJHNeMyWRy8MUpPxAZ2hY3hrT',
];
const HEX64 = 'a'.repeat(64);

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
const POLICY_VERSION = 'veilproof-policy-v1';

const CONSISTENT_CONTENT = JSON.stringify({
  verdict: 'consistent',
  points: ['Balance claim agrees with the balance metric.', 'No failed transactions were counted.'],
});

// Mock fetch. attestationMode: 'echo' (echo the request nonce),
// 'mismatch' (a fixed different nonce), 'model-only' (gateway absent,
// model report echoes), 'throw', 'http500'. completionContent is the
// model's reply text; completionStatus controls the HTTP status.
// Every call is recorded in `calls` in order.
function makeMockFetch({ attestationMode = 'echo', completionContent = CONSISTENT_CONTENT, completionStatus = 200 } = {}) {
  const calls = [];
  let lastEvidence = null;
  const fetchImpl = async (url, opts = {}) => {
    if (String(url).includes('/attestation/report')) {
      calls.push({ kind: 'attestation', url, headers: opts.headers || {} });
      if (attestationMode === 'throw') throw new Error('network down');
      if (attestationMode === 'http500') return { ok: false, status: 500, json: async () => ({}) };
      const nonce = new URL(url).searchParams.get('nonce');
      const evidence =
        attestationMode === 'mismatch'
          ? { gateway_attestation: { request_nonce: 'deadbeef'.repeat(8) }, model_attestations: [] }
          : attestationMode === 'model-only'
            ? { model_attestations: [{ request_nonce: nonce }] }
            : { gateway_attestation: { request_nonce: nonce }, model_attestations: [{ request_nonce: nonce }] };
      lastEvidence = evidence;
      return { ok: true, status: 200, json: async () => evidence };
    }
    if (String(url).includes('/chat/completions')) {
      const body = JSON.parse(opts.body);
      calls.push({ kind: 'completion', url, headers: opts.headers || {}, body });
      if (completionStatus !== 200) return { ok: false, status: completionStatus, json: async () => ({}) };
      return {
        ok: true,
        status: 200,
        json: async () => ({ id: 'chatcmpl-test', choices: [{ message: { content: completionContent } }] }),
      };
    }
    throw new Error(`unexpected URL ${url}`);
  };
  return { fetchImpl, calls, lastEvidence: () => lastEvidence };
}

// Run fn with VEILPROOF_NEAR_AI_API_KEY set to key (or deleted when
// key is undefined), restoring the original value afterwards.
async function withApiKey(key, fn) {
  const saved = process.env.VEILPROOF_NEAR_AI_API_KEY;
  try {
    if (key === undefined) delete process.env.VEILPROOF_NEAR_AI_API_KEY;
    else process.env.VEILPROOF_NEAR_AI_API_KEY = key;
    return await fn();
  } finally {
    if (saved === undefined) delete process.env.VEILPROOF_NEAR_AI_API_KEY;
    else process.env.VEILPROOF_NEAR_AI_API_KEY = saved;
  }
}

test('no key -> not_configured, summary null, fetch never called', async () => {
  let calls = 0;
  const neverFetch = async () => { calls += 1; throw new Error('must not be called'); };
  const result = await withApiKey(undefined, () =>
    analyseClaims({ claims: CLAIMS, metrics: METRICS, policyVersion: POLICY_VERSION }, { fetchImpl: neverFetch }));
  assert.equal(result.status, 'not_configured');
  assert.equal(result.summary, null);
  assert.equal(calls, 0);
});

test('happy path -> ok, structured attested summary, attestation before completion', async () => {
  const { fetchImpl, calls, lastEvidence } = makeMockFetch();
  const result = await withApiKey('sk-test-key', () =>
    analyseClaims({ claims: CLAIMS, metrics: METRICS, policyVersion: POLICY_VERSION }, { fetchImpl }));
  assert.equal(result.status, 'ok');
  const s = result.summary;
  assert.equal(s.provider, 'near-ai');
  assert.equal(s.model, DEFAULT_MODEL);
  assert.equal(s.verdict, 'consistent');
  assert.deepEqual(s.points, ['Balance claim agrees with the balance metric.', 'No failed transactions were counted.']);
  assert.equal(s.attestation.verifiable, true);
  assert.equal(s.attestation.nonceMatched, true);
  assert.match(s.attestation.ref, /^[0-9a-f]{64}$/);
  // ref pins the exact evidence the mock returned.
  const expectedRef = createHash('sha256').update(canonicalJson(lastEvidence()), 'utf8').digest('hex');
  assert.equal(s.attestation.ref, expectedRef);
  // Attestation preflight ran before the completion.
  assert.deepEqual(calls.map((c) => c.kind), ['attestation', 'completion']);
  // Completion request shape: no model substitution, enough tokens.
  const completion = calls.find((c) => c.kind === 'completion');
  assert.equal(completion.headers['x-no-aliasing'], 'true');
  assert.equal(completion.body.model, DEFAULT_MODEL);
  assert.ok(completion.body.max_tokens >= 800);
  assert.equal(completion.body.temperature, 0.3);
});

test('attestation echoed only by the model report -> still trusted', async () => {
  const { fetchImpl } = makeMockFetch({ attestationMode: 'model-only' });
  const result = await withApiKey('sk-test-key', () =>
    analyseClaims({ claims: CLAIMS, metrics: METRICS, policyVersion: POLICY_VERSION }, { fetchImpl }));
  assert.equal(result.status, 'ok');
  assert.equal(result.summary.attestation.verifiable, true);
  assert.equal(result.summary.attestation.nonceMatched, true);
  assert.match(result.summary.attestation.ref, /^[0-9a-f]{64}$/);
});

test('nonce mismatch -> summary returned but unattested, never attested', async () => {
  const { fetchImpl } = makeMockFetch({ attestationMode: 'mismatch' });
  const result = await withApiKey('sk-test-key', () =>
    analyseClaims({ claims: CLAIMS, metrics: METRICS, policyVersion: POLICY_VERSION }, { fetchImpl }));
  assert.equal(result.status, 'ok');
  assert.equal(result.summary.verdict, 'consistent');
  assert.equal(result.summary.attestation.verifiable, false);
  assert.equal(result.summary.attestation.nonceMatched, false);
  assert.equal(result.summary.attestation.ref, null);
});

test('attestation fetch throws -> unattested, analysis still completes', async () => {
  const { fetchImpl } = makeMockFetch({ attestationMode: 'throw' });
  const result = await withApiKey('sk-test-key', () =>
    analyseClaims({ claims: CLAIMS, metrics: METRICS, policyVersion: POLICY_VERSION }, { fetchImpl }));
  assert.equal(result.status, 'ok');
  assert.equal(result.summary.attestation.verifiable, false);
  assert.equal(result.summary.attestation.ref, null);
});

test('unparseable model output -> unparseable, summary null', async () => {
  const { fetchImpl } = makeMockFetch({ completionContent: 'this is not json at all, just prose' });
  const result = await withApiKey('sk-test-key', () =>
    analyseClaims({ claims: CLAIMS, metrics: METRICS, policyVersion: POLICY_VERSION }, { fetchImpl }));
  assert.equal(result.status, 'unparseable');
  assert.equal(result.summary, null);
});

test('empty model output -> empty_output, summary null', async () => {
  const { fetchImpl } = makeMockFetch({ completionContent: '   \n  ' });
  const result = await withApiKey('sk-test-key', () =>
    analyseClaims({ claims: CLAIMS, metrics: METRICS, policyVersion: POLICY_VERSION }, { fetchImpl }));
  assert.equal(result.status, 'empty_output');
  assert.equal(result.summary, null);
});

test('completion HTTP 500 -> api_error, summary null', async () => {
  const { fetchImpl } = makeMockFetch({ completionStatus: 500 });
  const result = await withApiKey('sk-test-key', () =>
    analyseClaims({ claims: CLAIMS, metrics: METRICS, policyVersion: POLICY_VERSION }, { fetchImpl }));
  assert.equal(result.status, 'api_error');
  assert.equal(result.summary, null);
});

test('leakage guard: address and tx hashes in metrics/claims never reach any request', async () => {
  const { fetchImpl, calls } = makeMockFetch();
  const leakyMetrics = {
    ...METRICS,
    accountId: DEMO_ADDRESS,
    address: DEMO_ADDRESS,
    txHashes: DEMO_TX_HASHES,
    snapshot: { account: { accountId: DEMO_ADDRESS }, txs: DEMO_TX_HASHES },
    prover: 'should-not-appear',
  };
  const leakyClaims = CLAIMS.map((c) => ({ ...c, address: DEMO_ADDRESS, hash: DEMO_TX_HASHES[0] }));
  const result = await withApiKey('sk-test-key', () =>
    analyseClaims({ claims: leakyClaims, metrics: leakyMetrics, policyVersion: POLICY_VERSION }, { fetchImpl }));
  assert.equal(result.status, 'ok');
  for (const call of calls) {
    const haystack = call.kind === 'completion' ? JSON.stringify(call.body) : call.url;
    assert.ok(!haystack.includes(DEMO_ADDRESS), `${call.kind} payload contains the wallet address`);
    for (const hash of DEMO_TX_HASHES) {
      assert.ok(!haystack.includes(hash), `${call.kind} payload contains tx hash ${hash.slice(0, 12)}`);
    }
  }
  // The sanitised payload the model actually saw has only allowed keys.
  const userContent = calls.find((c) => c.kind === 'completion').body.messages.find((m) => m.role === 'user').content;
  const sent = JSON.parse(userContent);
  assert.deepEqual(Object.keys(sent.metrics).sort(), Object.keys(METRICS).sort());
  for (const claim of sent.claims) {
    assert.deepEqual(Object.keys(claim).sort(), ['id', 'passed', 'threshold', 'value']);
  }
});

test('deterministic guard: model "consistent" on a self-contradictory claim -> inconsistent', async () => {
  const { fetchImpl } = makeMockFetch();
  const badClaims = [
    { id: 'balance_at_least', passed: true, value: '100', threshold: '5000000000000000000000000' },
  ];
  const result = await withApiKey('sk-test-key', () =>
    analyseClaims({ claims: badClaims, metrics: { balanceYocto: '100' }, policyVersion: POLICY_VERSION }, { fetchImpl }));
  assert.equal(result.status, 'ok');
  assert.equal(result.summary.verdict, 'inconsistent');
  assert.ok(result.summary.points.some((p) => p.startsWith('Deterministic check:')));
});

test('model "inconsistent" verdict is kept when claims check out', async () => {
  const content = JSON.stringify({ verdict: 'inconsistent', points: ['Volume metric is missing, cannot check the volume claim.'] });
  const { fetchImpl } = makeMockFetch({ completionContent: content });
  const result = await withApiKey('sk-test-key', () =>
    analyseClaims({ claims: CLAIMS, metrics: METRICS, policyVersion: POLICY_VERSION }, { fetchImpl }));
  assert.equal(result.status, 'ok');
  assert.equal(result.summary.verdict, 'inconsistent');
  assert.deepEqual(result.summary.points, ['Volume metric is missing, cannot check the volume claim.']);
});

test('maxTokens floors at 800', async () => {
  const { fetchImpl, calls } = makeMockFetch();
  await withApiKey('sk-test-key', () =>
    analyseClaims({ claims: CLAIMS, metrics: METRICS, policyVersion: POLICY_VERSION }, { fetchImpl, maxTokens: 100 }));
  assert.equal(calls.find((c) => c.kind === 'completion').body.max_tokens, 800);
});

test('report interop: returned summary is accepted by buildReport as aiSummary', async () => {
  const { fetchImpl } = makeMockFetch();
  const result = await withApiKey('sk-test-key', () =>
    analyseClaims({ claims: CLAIMS, metrics: METRICS, policyVersion: POLICY_VERSION }, { fetchImpl }));
  assert.equal(result.status, 'ok');
  const report = buildReport({
    proverAddressHash: HEX64,
    claims: CLAIMS,
    policyVersion: POLICY_VERSION,
    aiSummary: result.summary,
    evidenceRefs: { dataHash: HEX64, attestationRef: result.summary.attestation.ref },
    expiresAt: '1825497600000000000',
  });
  assert.equal(report.aiSummary, result.summary);
  assert.equal(report.evidenceRefs.attestationRef, result.summary.attestation.ref);
});

test('sanitiseMetrics drops forbidden keys and keeps allowed ones', () => {
  const clean = sanitiseMetrics({
    balanceYocto: '100',
    txCount: 4,
    address: DEMO_ADDRESS,
    accountId: DEMO_ADDRESS,
    txHashes: DEMO_TX_HASHES,
    snapshot: { accountId: DEMO_ADDRESS },
    weird: { nested: DEMO_ADDRESS },
  });
  assert.deepEqual(clean, { balanceYocto: '100', txCount: 4 });
  assert.deepEqual(sanitiseMetrics(undefined), {});
  assert.deepEqual(sanitiseMetrics(null), {});
});

test('sanitiseClaims drops extra fields and throws on malformed claims', () => {
  const clean = sanitiseClaims([{ ...CLAIMS[0], address: DEMO_ADDRESS, extra: 1 }]);
  assert.deepEqual(clean, [CLAIMS[0]]);
  assert.throws(() => sanitiseClaims('not-an-array'), /claims must be an array/);
  assert.throws(() => sanitiseClaims([{ id: 'balance_at_least', passed: 'yes', value: '1', threshold: '1' }]), /passed must be a boolean/);
});

test('checkClaimsConsistent flags contradictions and passes clean claims', () => {
  assert.deepEqual(checkClaimsConsistent(CLAIMS), { consistent: true, problems: [] });
  const bad = checkClaimsConsistent([
    { id: 'balance_at_least', passed: true, value: '100', threshold: '1000' },
    { id: 'no_failed_txs_in_window', passed: true, value: 2, threshold: 30 },
    { id: 'volume_in_window', passed: true, value: '0', threshold: 30 },
  ]);
  assert.equal(bad.consistent, false);
  assert.equal(bad.problems.length, 3);
});

test('parseModelOutput tolerates fences and rejects bad verdicts', () => {
  assert.deepEqual(
    parseModelOutput('```json\n{"verdict": "inconsistent", "points": ["a", "b"]}\n```'),
    { verdict: 'inconsistent', points: ['a', 'b'] },
  );
  assert.deepEqual(
    parseModelOutput('Some preamble {"verdict": "consistent", "points": []} trailing'),
    { verdict: 'consistent', points: [] },
  );
  assert.equal(parseModelOutput('{"verdict": "maybe", "points": []}'), null);
  assert.equal(parseModelOutput('not json'), null);
  assert.equal(parseModelOutput(''), null);
  assert.equal(parseModelOutput('{"verdict": "consistent"}'), null);
});

const SCORE = {
  version: 'score-v1',
  value: 850,
  band: 'strong',
  components: [
    { id: 'sustained_balance', points: 300, max: 300, measured: true },
    { id: 'time_weighted_balance', points: 200, max: 200, measured: true },
    { id: 'activity', points: 120, max: 200, measured: true },
    { id: 'volume', points: 130, max: 150, measured: true },
    { id: 'no_failed', points: 100, max: 100, measured: true },
    { id: 'staked', points: 0, max: 50, measured: true },
  ],
};
const UNDERWRITE_CONTENT = JSON.stringify({
  verdict: 'lend',
  suggestedLimitNear: 5,
  confidence: 'high',
  points: ['Strong sustained balance with clean history.'],
});

test('sanitiseScore keeps the score shape and throws on malformed scores', () => {
  assert.deepEqual(sanitiseScore({ ...SCORE, extra: 'drop me', address: DEMO_ADDRESS }), SCORE);
  assert.throws(() => sanitiseScore({ ...SCORE, value: 1001 }), /integer 0-1000/);
  assert.throws(() => sanitiseScore({ ...SCORE, band: 'great' }), /thin, building, solid or strong/);
  assert.throws(() => sanitiseScore({ ...SCORE, components: [{ id: 'x', points: 1, max: 1 }] }), /measured must be a boolean/);
  assert.throws(() => sanitiseScore(null), /must be an object/);
});

test('parseUnderwritingOutput validates verdicts and coerces limit/confidence', () => {
  assert.deepEqual(parseUnderwritingOutput(UNDERWRITE_CONTENT), {
    verdict: 'lend',
    suggestedLimitNear: 5,
    confidence: 'high',
    points: ['Strong sustained balance with clean history.'],
  });
  assert.deepEqual(parseUnderwritingOutput('{"verdict": "decline", "points": []}'), {
    verdict: 'decline',
    suggestedLimitNear: null,
    confidence: 'low',
    points: [],
  });
  assert.equal(parseUnderwritingOutput('{"verdict": "maybe", "points": []}'), null);
  assert.equal(parseUnderwritingOutput('not json'), null);
});

test('underwriting: lend verdict on a strong score, attested, score in the payload', async () => {
  const { fetchImpl, calls } = makeMockFetch({ completionContent: UNDERWRITE_CONTENT });
  const result = await withApiKey('test-key', () =>
    analyseUnderwriting({ claims: CLAIMS, metrics: METRICS, score: SCORE, policyVersion: POLICY_VERSION }, { fetchImpl }));
  assert.equal(result.status, 'ok');
  assert.equal(result.summary.role, 'underwriting');
  assert.equal(result.summary.verdict, 'lend');
  assert.equal(result.summary.suggestedLimitNear, 5);
  assert.equal(result.summary.confidence, 'high');
  assert.equal(result.summary.attestation.verifiable, true);
  const completion = calls.find((c) => c.kind === 'completion');
  const sent = JSON.parse(completion.body.messages[1].content);
  assert.equal(sent.score.value, 850);
  assert.equal(JSON.stringify(completion.body).includes(DEMO_ADDRESS), false);
});

test('underwriting: deterministic guard turns lend into decline on a thin score', async () => {
  const thin = { ...SCORE, value: 150, band: 'thin' };
  const { fetchImpl } = makeMockFetch({ completionContent: UNDERWRITE_CONTENT });
  const result = await withApiKey('test-key', () =>
    analyseUnderwriting({ claims: CLAIMS, metrics: METRICS, score: thin, policyVersion: POLICY_VERSION }, { fetchImpl }));
  assert.equal(result.status, 'ok');
  assert.equal(result.summary.verdict, 'decline');
  assert.equal(result.summary.suggestedLimitNear, null);
  assert.match(result.summary.points[0], /Deterministic guard/);
});

test('underwriting: no key -> not_configured, summary null', async () => {
  const { fetchImpl } = makeMockFetch({ completionContent: UNDERWRITE_CONTENT });
  const result = await withApiKey(undefined, () =>
    analyseUnderwriting({ claims: CLAIMS, metrics: METRICS, score: SCORE, policyVersion: POLICY_VERSION }, { fetchImpl }));
  assert.equal(result.status, 'not_configured');
  assert.equal(result.summary, null);
});

test('underwriting: malformed score throws like malformed claims', async () => {
  const { fetchImpl } = makeMockFetch({ completionContent: UNDERWRITE_CONTENT });
  await assert.rejects(
    withApiKey('test-key', () =>
      analyseUnderwriting({ claims: CLAIMS, metrics: METRICS, score: { ...SCORE, value: -1 }, policyVersion: POLICY_VERSION }, { fetchImpl })),
    /integer 0-1000/,
  );
});
