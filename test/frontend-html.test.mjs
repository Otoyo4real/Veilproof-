// Sanity checks for public/index.html + public/app.js.
//
// This VM has no working local Chrome, so the page is validated by
// parsing instead of rendering: the required element ids exist, every
// id app.js looks up is present in the HTML, the wallet library and
// the app module are wired up, and the page hardcodes no wallet
// address (the demo address lives only in demo-history.json, loaded
// at runtime for the wallet it belongs to).

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const html = readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
const appJs = readFileSync(new URL('../public/app.js', import.meta.url), 'utf8');

const REQUIRED_IDS = [
  'previewAddress',
  'connectBtn',
  'walletStatus',
  'accountLine',
  'challengeBtn',
  'challengeOut',
  'txHashes',
  'loadDemoBtn',
  'fetchSnapshotBtn',
  'snapshotOut',
  'polBalance',
  'polStaked',
  'polMinTx',
  'polTxWindow',
  'polMinVol',
  'polVolWindow',
  'polNoFailed',
  'evaluateBtn',
  'claimsOut',
  'discloseList',
  'expirySelect',
  'aiBtn',
  'aiStatus',
  'buildReportBtn',
  'reportOut',
  'downloadReportBtn',
  'downloadDisclosureBtn',
  'publishBox',
  'publishCost',
  'publishConfirm',
  'publishBtn',
  'publishOut',
];

test('index.html is a complete document with the wallet lib and the app module', () => {
  assert.ok(html.startsWith('<!DOCTYPE html>'), 'must start with a doctype');
  assert.ok(html.trimEnd().endsWith('</html>'), 'must end with </html>');
  assert.ok(
    html.includes('https://cdn.jsdelivr.net/npm/@fastnear/wallet@2.5.0/dist/umd/browser.global.js'),
    'must load the @fastnear/wallet UMD bundle (same version as Genesis)',
  );
  assert.ok(html.includes('<script type="module" src="app.js"></script>'), 'must load app.js as a module');
  assert.ok(html.includes('href="verify.html"'), 'must link to the verifier portal');
  assert.ok(html.includes('registry.veilproof.testnet'), 'must name the registry contract');
  assert.ok(html.includes('testnet'), 'must say testnet');
});

test('every required element id exists in index.html', () => {
  for (const id of REQUIRED_IDS) {
    assert.ok(html.includes(`id="${id}"`), `index.html is missing id="${id}"`);
  }
  const seen = new Set();
  for (const id of REQUIRED_IDS) {
    assert.ok(!seen.has(id), `duplicate required id ${id}`);
    seen.add(id);
  }
});

test('every id app.js looks up exists in index.html', () => {
  const used = [...appJs.matchAll(/\$\('([^']+)'\)/g)].map((m) => m[1]);
  const unique = [...new Set(used)];
  assert.ok(unique.length > 20, `expected app.js to look up many ids, found ${unique.length}`);
  for (const id of unique) {
    assert.ok(html.includes(`id="${id}"`), `app.js looks up id="${id}" but index.html has no such element`);
  }
});

test('index.html hardcodes no wallet address', () => {
  // registry.veilproof.testnet is the contract, not a wallet — it is
  // supposed to be named. Strip it first, then no wallet address may
  // remain.
  const withoutRegistry = html.replaceAll('registry.veilproof.testnet', '');
  assert.ok(!withoutRegistry.includes('veilproof-demo.testnet'), 'demo wallet address must not be hardcoded in the page');
  assert.ok(!withoutRegistry.includes('veilproof.testnet'), 'deployer wallet address must not be hardcoded in the page');
  assert.ok(!html.includes('testnet-accounts'), 'key file must never be referenced from the page');
});

test('preview flow: paste an address to preview, wallet only to sign and publish', () => {
  // The preview is read-only and needs no wallet; ownership is proved
  // only by the connected wallet that owns the previewed address.
  assert.ok(html.includes('id="previewAddress"'), 'index.html must have the preview address input');
  assert.ok(appJs.includes('readPreviewAddress'), 'app.js must read and validate the preview address');
  assert.ok(appJs.includes('previewMatchesConnected'), 'app.js must bind signing/publishing to the owning wallet');
  assert.ok(
    appJs.includes('if (!previewMatchesConnected())'),
    'publish() must refuse to sign when the connected wallet does not own the previewed address',
  );
  // The demo load and the snapshot fetch must not be gated on a wallet.
  assert.ok(!appJs.includes("$('loadDemoBtn').disabled = !connected"), 'demo load must not need a wallet');
  assert.ok(!appJs.includes("$('fetchSnapshotBtn').disabled = !connected"), 'snapshot fetch must not need a wallet');
  // The prover commitment, tripwire and disclosure must use the
  // previewed address, not the connected wallet.
  assert.ok(appJs.includes('sha256Hex(state.previewAddress)'), 'prover commitment must hash the previewed address');
  assert.ok(appJs.includes('buildDisclosurePackage(report, state.previewAddress'), 'disclosure must use the previewed address');
});

test('app.js keeps private data out of the AI request and the public report', () => {
  // The metrics builder is an allowlist by construction.
  assert.ok(appJs.includes('Allowlist by construction'), 'metrics builder must carry its allowlist comment');
  assert.ok(!/body:\s*JSON\.stringify\(\{\s*claims:[^}]*address/.test(appJs), 'AI request must not include the address');
  // The report is tripwire-checked before it is shown or published.
  assert.ok(appJs.includes('assertPublicReportClean('), 'report must pass the clean check');
  assert.ok(appJs.includes('buildDisclosurePackage('), 'disclosure package must be built from the report');
  // Publish goes to the registry only, with the contract method name.
  assert.ok(appJs.includes("methodName: 'publish_claim'"), 'publish must call publish_claim');
  assert.ok(appJs.includes('receiverId: REGISTRY'), 'publish must target the registry contract');
});
