// Tests for POST /api/analyze (api/analyze.js).
//
// The route is a thin guard around src/ai-analysis.js: POST only, no
// leaking fields (address / snapshot / tx hashes are refused), and the
// module's statuses pass through. No network is used except through a
// stubbed fetch; no real key is needed (a fake env value stands in
// for the "configured" path, and the stub never leaves the process).

import test from 'node:test';
import assert from 'node:assert/strict';

import handler from '../api/analyze.js';

const KEY_ENV = 'VEILPROOF_NEAR_AI_API_KEY';
const CLAIMS = [
  { id: 'balance_at_least', passed: true, value: '5000000000000000000000000', threshold: '1000000000000000000000000' },
];
const METRICS = { balanceYocto: '5000000000000000000000000', txCount: 2, successTxCount: 2, failedTxCount: 0 };

function mockReq(method, body) {
  return { method, body };
}

function mockRes() {
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
  return res;
}

async function callRoute(method, body) {
  const req = mockReq(method, body);
  const res = mockRes();
  await handler(req, res);
  return res;
}

function withKey(value, fn) {
  const saved = process.env[KEY_ENV];
  if (value === undefined) delete process.env[KEY_ENV];
  else process.env[KEY_ENV] = value;
  return Promise.resolve()
    .then(fn)
    .finally(() => {
      if (saved === undefined) delete process.env[KEY_ENV];
      else process.env[KEY_ENV] = saved;
    });
}

function withFetch(stub, fn) {
  const saved = globalThis.fetch;
  globalThis.fetch = stub;
  return Promise.resolve()
    .then(fn)
    .finally(() => {
      globalThis.fetch = saved;
    });
}

test('GET is rejected with 405', async () => {
  const res = await callRoute('GET', undefined);
  assert.equal(res.statusCode, 405);
  assert.equal(res.body.error, 'method_not_allowed');
  assert.equal(res.headers.Allow, 'POST');
});

test('without a key the route answers not_configured and never calls the API', async () => {
  await withKey(undefined, async () => {
    let called = false;
    await withFetch(
      async () => {
        called = true;
        throw new Error('must not be called');
      },
      async () => {
        const res = await callRoute('POST', { claims: CLAIMS, metrics: METRICS, policyVersion: 'veilproof-policy-v1' });
        assert.equal(res.statusCode, 200);
        assert.equal(res.body.status, 'not_configured');
        assert.equal(res.body.summary, null);
      },
    );
    assert.equal(called, false);
  });
});

test('a request carrying the address is refused, not sanitised silently', async () => {
  const res = await callRoute('POST', {
    claims: CLAIMS,
    metrics: METRICS,
    policyVersion: 'veilproof-policy-v1',
    address: 'veilproof-demo.testnet',
  });
  assert.equal(res.statusCode, 400);
  assert.equal(res.body.error, 'forbidden_field');
  assert.equal(res.body.field, 'address');
});

test('malformed claims are a 400, not a 500', async () => {
  await withKey('fake-key-for-test', async () => {
    const res = await callRoute('POST', { claims: 'not-an-array', metrics: METRICS, policyVersion: 'veilproof-policy-v1' });
    assert.equal(res.statusCode, 400);
    assert.equal(res.body.error, 'invalid_input');
  });
});

test('ok path: attested summary passes through, and junk address/tx fields in metrics never reach the model', async () => {
  await withKey('fake-key-for-test', async () => {
    let capturedCompletionBody = null;
    const stub = async (url, init) => {
      if (String(url).includes('/attestation/report')) {
        const nonce = new URL(url).searchParams.get('nonce');
        return { ok: true, json: async () => ({ gateway_attestation: { request_nonce: nonce } }) };
      }
      if (String(url).includes('/chat/completions')) {
        capturedCompletionBody = String(init.body);
        return {
          ok: true,
          json: async () => ({
            choices: [
              {
                message: {
                  content: JSON.stringify({
                    verdict: 'consistent',
                    points: ['Balance claim agrees with the balance metric.'],
                  }),
                },
              },
            ],
          }),
        };
      }
      throw new Error(`unexpected fetch to ${url}`);
    };
    await withFetch(stub, async () => {
      const res = await callRoute('POST', {
        claims: CLAIMS,
        // A leaking client stuffing private fields into metrics: the
        // module's allowlist must drop them before any request is made.
        metrics: {
          ...METRICS,
          address: 'veilproof-demo.testnet',
          accountId: 'veilproof-demo.testnet',
          txHash: 'EQeaPK7R7nzT14a6e5kc685Yug45LDMxP4K7YhTxYn9g',
        },
        policyVersion: 'veilproof-policy-v1',
      });
      assert.equal(res.statusCode, 200);
      assert.equal(res.body.status, 'ok');
      assert.equal(res.body.summary.provider, 'near-ai');
      assert.equal(res.body.summary.verdict, 'consistent');
      assert.equal(res.body.summary.attestation.verifiable, true);
      assert.equal(res.body.summary.attestation.nonceMatched, true);
      assert.match(res.body.summary.attestation.ref, /^[0-9a-f]{64}$/);
      // The model request carried none of the private fields.
      assert.ok(capturedCompletionBody !== null, 'completion was called');
      assert.ok(!capturedCompletionBody.includes('veilproof-demo.testnet'), 'address leaked to the model');
      assert.ok(!capturedCompletionBody.includes('EQeaPK7R7nzT14a6e5kc685Yug45LDMxP4K7YhTxYn9g'), 'tx hash leaked to the model');
      // And neither did the route's response.
      assert.ok(!JSON.stringify(res.body).includes('veilproof-demo.testnet'));
    });
  });
});

test('a failing completion endpoint surfaces as api_error, not a 500', async () => {
  await withKey('fake-key-for-test', async () => {
    const stub = async (url) => {
      if (String(url).includes('/attestation/report')) {
        const nonce = new URL(url).searchParams.get('nonce');
        return { ok: true, json: async () => ({ gateway_attestation: { request_nonce: nonce } }) };
      }
      return { ok: false, status: 500, json: async () => ({}) };
    };
    await withFetch(stub, async () => {
      const res = await callRoute('POST', { claims: CLAIMS, metrics: METRICS, policyVersion: 'veilproof-policy-v1' });
      assert.equal(res.statusCode, 200);
      assert.equal(res.body.status, 'api_error');
      assert.equal(res.body.summary, null);
    });
  });
});

const SCORE = {
  version: 'score-v1',
  value: 850,
  band: 'strong',
  components: [{ id: 'sustained_balance', points: 300, max: 300, measured: true }],
};
const UNDERWRITE_CONTENT = JSON.stringify({
  verdict: 'lend_with_limits',
  suggestedLimitNear: 2,
  confidence: 'medium',
  points: ['Solid score, but activity is thin.'],
});

function underwriteStub() {
  return async (url) => {
    if (String(url).includes('/attestation/report')) {
      const nonce = new URL(url).searchParams.get('nonce');
      return { ok: true, status: 200, json: async () => ({ gateway_attestation: { request_nonce: nonce } }) };
    }
    return {
      ok: true,
      status: 200,
      json: async () => ({ choices: [{ message: { content: UNDERWRITE_CONTENT } }] }),
    };
  };
}

test('underwriting mode returns an advisory verdict with role underwriting', async () => {
  const res = await withKey('test-key', () =>
    withFetch(underwriteStub(), () =>
      callRoute('POST', { mode: 'underwriting', claims: CLAIMS, metrics: METRICS, score: SCORE, policyVersion: 'veilproof-policy-v2' }),
    ),
  );
  assert.equal(res.statusCode, 200);
  assert.equal(res.body.status, 'ok');
  assert.equal(res.body.summary.role, 'underwriting');
  assert.equal(res.body.summary.verdict, 'lend_with_limits');
  assert.equal(res.body.summary.suggestedLimitNear, 2);
});

test('underwriting without a score is a 400 (malformed input), not a server error', async () => {
  const res = await withKey('test-key', () =>
    withFetch(underwriteStub(), () =>
      callRoute('POST', { mode: 'underwriting', claims: CLAIMS, metrics: METRICS, policyVersion: 'veilproof-policy-v2' }),
    ),
  );
  assert.equal(res.statusCode, 400);
  assert.equal(res.body.error, 'invalid_input');
});

test('unknown mode is a 400', async () => {
  const res = await callRoute('POST', { mode: 'audit', claims: CLAIMS, metrics: METRICS, policyVersion: 'veilproof-policy-v2' });
  assert.equal(res.statusCode, 400);
  assert.equal(res.body.error, 'invalid_input');
});
