// Homepage live demo — verifies the published demo claim right here
// on the page, against the live testnet registry. Same verify logic
// as the verifier portal (public/js/verify-browser.js, parity-tested
// against src/verify-report.js), same demo files the portal loads.
// The disclosure package is the DEMO wallet's — a throwaway testnet
// account whose address is already public in demo/history.json — so
// showing it here leaks nothing.

import { verifyReport } from './js/verify-browser.js';

const RPC_URL = 'https://rpc.testnet.near.org';
const REGISTRY = 'registry.veilproof.testnet';

const $ = (id) => document.getElementById(id);
const esc = (s) =>
  String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');

function base64Utf8(str) {
  const bytes = new TextEncoder().encode(str);
  let bin = '';
  bytes.forEach((b) => {
    bin += String.fromCharCode(b);
  });
  return btoa(bin);
}

async function rpcView(method, args) {
  const res = await fetch(RPC_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 'veilproof-demo',
      method: 'query',
      params: {
        request_type: 'call_function',
        account_id: REGISTRY,
        method_name: method,
        args_base64: base64Utf8(JSON.stringify(args)),
        finality: 'final',
      },
    }),
  });
  const json = await res.json();
  if (json.error) throw new Error(json.error.message || json.error.name || 'RPC error');
  const text = new TextDecoder().decode(new Uint8Array(json.result.result));
  return JSON.parse(text);
}

function renderDemo(result, report) {
  const banner = $('demoBanner');
  banner.textContent = result.valid ? 'VALID — this report verifies.' : 'INVALID — this report does not verify.';
  banner.className = 'banner ' + (result.valid ? 'valid' : 'invalid');
  $('demoChecks').innerHTML = result.checks
    .map(
      (c) =>
        '<div class="check ' + (c.passed ? 'pass' : 'fail') + '"><span class="mark">' +
        (c.passed ? '✓' : '✗') + ' ' + esc(c.check) + '</span><div class="detail">' + esc(c.detail) + '</div></div>',
    )
    .join('');
  $('demoClaims').innerHTML =
    '<table><tr><th>Claim</th><th>Passed</th><th>Value</th><th>Threshold</th></tr>' +
    report.claims
      .map(
        (c) =>
          '<tr><td>' + esc(c.id) + '</td><td>' + (c.passed ? 'yes' : 'NO') + '</td><td class="mono">' +
          esc(c.value) + '</td><td class="mono">' + esc(c.threshold) + '</td></tr>',
      )
      .join('') +
    '</table>';
  let expires = 'unreadable';
  try {
    expires = new Date(Number(BigInt(report.expiresAt) / 1000000n)).toISOString().slice(0, 10);
  } catch (_) {
    /* keep unreadable */
  }
  const ai =
    report.aiSummary === null
      ? 'Not analysed.'
      : report.aiSummary.role === 'underwriting'
        ? 'Underwriting (advisory): ' +
          esc(report.aiSummary.verdict) +
          (report.aiSummary.suggestedLimitNear !== null && report.aiSummary.suggestedLimitNear !== undefined
            ? ' — suggested limit ' + esc(String(report.aiSummary.suggestedLimitNear)) + ' NEAR'
            : '') +
          ' — NEAR AI Cloud, attested' + (report.aiSummary.attestation?.verifiable ? ' (nonce matched).' : '.')
        : esc(report.aiSummary.verdict) + ' — NEAR AI Cloud, attested' + (report.aiSummary.attestation?.verifiable ? ' (nonce matched).' : '.');
  const scoreLine = report.score
    ? '<p>Credit score: <strong>' +
      report.score.value +
      ' / 1000 (' +
      esc(report.score.band) +
      ')</strong> — recomputable by any app from the same disclosure package.</p>' +
      '<table><tr><th>Component</th><th>Points</th><th>Measured</th></tr>' +
      report.score.components
        .map((c) => '<tr><td>' + esc(c.label) + '</td><td>' + c.points + ' / ' + c.max + '</td><td>' + (c.measured ? 'yes' : 'not measured') + '</td></tr>')
        .join('') +
      '</table>'
    : '<p>Credit score: not scored.</p>';
  $('demoFacts').innerHTML =
    '<p>Report ID: <span class="mono">' + esc(report.reportId) + '</span></p>' +
    scoreLine +
    '<p>AI summary: ' + ai + '</p>' +
    '<p>Expires: <span class="mono">' + esc(expires) + '</span></p>';
  $('demoResult').hidden = false;
}

async function runDemo() {
  const status = $('demoStatus');
  const btn = $('demoRunBtn');
  $('demoResult').hidden = true;
  status.textContent = '';
  btn.disabled = true;
  try {
    status.textContent = 'Loading the published demo claim…';
    const [reportRes, disclosureRes, policyRes] = await Promise.all([
      fetch('demo-report.json'),
      fetch('demo-disclosure.json'),
      fetch('demo-policy.json'),
    ]);
    if (!reportRes.ok || !disclosureRes.ok || !policyRes.ok) {
      throw new Error('demo files could not be loaded');
    }
    const report = await reportRes.json();
    const disclosurePackage = await disclosureRes.json();
    const policy = await policyRes.json();
    status.textContent = 'Fetching the onchain record…';
    const record = await rpcView('get_claim', { claim_id: report.reportId });
    if (record === null || record === undefined) {
      throw new Error('no onchain record found for the demo claim — it may have expired');
    }
    const valid = await rpcView('is_claim_valid', { claim_id: report.reportId });
    status.textContent = 'Verifying…';
    const nowNs = (BigInt(Date.now()) * 1000000n).toString();
    const result = await verifyReport({
      report,
      onchainRecord: {
        report_hash: record.report_hash,
        evidence_hash: record.evidence_hash,
        policy_hash: record.policy_hash,
        valid,
      },
      disclosurePackage,
      policy,
      nowNs,
    });
    status.textContent = '';
    renderDemo(result, report);
  } catch (err) {
    status.textContent = 'Demo failed: ' + err.message;
    status.className = 'error';
  } finally {
    btn.disabled = false;
  }
}

window.addEventListener('load', () => {
  $('demoRunBtn').addEventListener('click', runDemo);
});
