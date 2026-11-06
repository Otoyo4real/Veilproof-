// POST /api/analyze — NEAR AI analysis for a VeilProof report.
//
// The browser sends ONLY claim-level data: { claims, metrics,
// policyVersion }. The address, the snapshot and transaction hashes
// never leave the prover's browser for this call — the route rejects
// any request carrying them (defence in depth; src/ai-analysis.js
// also sanitises by allowlist, so a leaking client cannot smuggle
// them through either).
//
// The key comes from env VEILPROOF_NEAR_AI_API_KEY ONLY, read at call
// time inside src/ai-analysis.js. Without it the route answers
// { status: 'not_configured', summary: null } and the report stays
// honestly unanalysed. The key is never logged, never returned, and
// never stored in the repo.
//
// Why this route imports ../src/ai-analysis.js directly: VeilProof is
// an ESM project ("type": "module"), so the serverless function and
// the shared module are the same module system and Vercel traces the
// relative import into the function bundle. The Genesis duplication
// (api/pay-job.js re-implementing its judge) was a CJS/ESM mismatch —
// Genesis api/ files are CommonJS while its src/ is ESM — and even
// there api/nft-card.js already requires ../nft/cards.json. The
// route test (test/analyze-route.test.mjs) imports this file and
// exercises the real import path.

import { analyseClaims } from '../src/ai-analysis.js';

// Top-level keys that must never arrive here. A client sending them is
// leaking private data; refuse instead of silently dropping it, so a
// broken client is noticed rather than "working" while leaking.
const FORBIDDEN_TOP_LEVEL_KEYS = new Set([
  'address',
  'accountId',
  'snapshot',
  'txHashes',
  'txs',
  'prover',
]);

function readBody(req) {
  const body = req.body;
  if (body === undefined || body === null) return {};
  if (typeof body === 'string') {
    if (body.trim() === '') return {};
    return JSON.parse(body);
  }
  return body;
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'method_not_allowed' });
  }

  let body;
  try {
    body = readBody(req);
  } catch {
    return res.status(400).json({ error: 'invalid_json' });
  }
  if (body === null || typeof body !== 'object' || Array.isArray(body)) {
    return res.status(400).json({ error: 'invalid_body' });
  }
  for (const key of FORBIDDEN_TOP_LEVEL_KEYS) {
    if (key in body) {
      return res.status(400).json({ error: 'forbidden_field', field: key });
    }
  }

  try {
    const { status, summary, error } = await analyseClaims({
      claims: body.claims,
      metrics: body.metrics,
      policyVersion: body.policyVersion,
    });
    // Never echo the request back, and never include anything the
    // module did not return: the response carries only the status and
    // the structured summary (or null).
    return res.status(200).json({
      status,
      summary,
      ...(error !== undefined ? { error } : {}),
    });
  } catch (err) {
    // analyseClaims throws only on malformed input (claims not an
    // array, malformed claim, bad policyVersion). That is a caller
    // error, not a server error — and the message carries no secrets.
    return res.status(400).json({
      error: 'invalid_input',
      detail: String(err && err.message ? err.message : err).slice(0, 200),
    });
  }
}
