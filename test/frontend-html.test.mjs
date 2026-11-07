// Sanity checks for the multi-page site + public/app.js.
//
// This VM has no working local Chrome, so the pages are validated by
// parsing instead of rendering: the required element ids exist on the
// page that owns them (the prover lives on prove.html, the live demo
// on demo.html), every id app.js looks up is present on prove.html,
// the wallet library and the app module are wired up there, and no
// page hardcodes a wallet address (the demo address lives only in
// demo-history.json, loaded at runtime for the wallet it belongs to).

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const html = readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
const proveHtml = readFileSync(new URL('../public/prove.html', import.meta.url), 'utf8');
const demoHtml = readFileSync(new URL('../public/demo.html', import.meta.url), 'utf8');
const appJs = readFileSync(new URL('../public/app.js', import.meta.url), 'utf8');

// The prover ids live on prove.html; the live demo ids live on demo.html.
const PROVER_IDS = [
  'provingLine',
  'proveConnectedBtn',
  'mismatchOut',
  'connectBtn',
  'walletStatus',
  'accountLine',
  'challengeBtn',
  'challengeOut',
  'txHashes',
  'linkedAddresses',
  'linkedTxHashes',
  'sampleWindow',
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
  'polAggBalance',
  'polSustained',
  'polTimeWeighted',
  'polAggMinTx',
  'polAggTxWindow',
  'polAggMinVol',
  'polAggVolWindow',
  'evaluateBtn',
  'claimsOut',
  'scoreOut',
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

const DEMO_IDS = [
  'demoRunBtn',
  'demoStatus',
  'demoResult',
  'demoBanner',
  'demoChecks',
  'demoClaims',
  'demoFacts',
];

const ALL_PAGES = [
  ['index.html', html],
  ['prove.html', proveHtml],
  ['demo.html', demoHtml],
  ['verify.html', readFileSync(new URL('../public/verify.html', import.meta.url), 'utf8')],
  ['how-it-works.html', readFileSync(new URL('../public/how-it-works.html', import.meta.url), 'utf8')],
];

test('index.html is a complete landing document and links every page', () => {
  assert.ok(html.startsWith('<!DOCTYPE html>'), 'must start with a doctype');
  assert.ok(html.trimEnd().endsWith('</html>'), 'must end with </html>');
  assert.ok(html.includes('width=device-width, initial-scale=1'), 'must set the viewport');
  for (const page of ['prove.html', 'demo.html', 'verify.html', 'how-it-works.html']) {
    assert.ok(html.includes(`href="${page}"`), `landing page must link to ${page}`);
  }
  assert.ok(html.includes('registry.veilproof.testnet'), 'must name the registry contract');
  assert.ok(html.includes('testnet'), 'must say testnet');
});

test('prove.html is a complete document with the wallet lib and the app module', () => {
  assert.ok(proveHtml.startsWith('<!DOCTYPE html>'), 'must start with a doctype');
  assert.ok(proveHtml.trimEnd().endsWith('</html>'), 'must end with </html>');
  assert.ok(
    proveHtml.includes('https://cdn.jsdelivr.net/npm/@fastnear/wallet@2.5.0/dist/umd/browser.global.js'),
    'must load the @fastnear/wallet UMD bundle (same version as Genesis)',
  );
  assert.ok(proveHtml.includes('<script type="module" src="app.js"></script>'), 'must load app.js as a module');
  assert.ok(proveHtml.includes('href="verify.html"'), 'must link to the verifier portal');
  assert.ok(proveHtml.includes('registry.veilproof.testnet'), 'must name the registry contract');
  assert.ok(proveHtml.includes('testnet'), 'must say testnet');
});

test('every required element id exists on the page that owns it', () => {
  for (const id of PROVER_IDS) {
    assert.ok(proveHtml.includes(`id="${id}"`), `prove.html is missing id="${id}"`);
  }
  for (const id of DEMO_IDS) {
    assert.ok(demoHtml.includes(`id="${id}"`), `demo.html is missing id="${id}"`);
  }
  const seen = new Set();
  for (const id of [...PROVER_IDS, ...DEMO_IDS]) {
    assert.ok(!seen.has(id), `duplicate required id ${id}`);
    seen.add(id);
  }
});

test('every id app.js looks up exists in prove.html', () => {
  const used = [...appJs.matchAll(/\$\('([^']+)'\)/g)].map((m) => m[1]);
  const unique = [...new Set(used)];
  assert.ok(unique.length > 20, `expected app.js to look up many ids, found ${unique.length}`);
  for (const id of unique) {
    assert.ok(proveHtml.includes(`id="${id}"`), `app.js looks up id="${id}" but prove.html has no such element`);
  }
});

test('no page hardcodes a wallet address', () => {
  // registry.veilproof.testnet is the contract, not a wallet — it is
  // supposed to be named. Strip it first, then no wallet address may
  // remain on any page.
  for (const [name, src] of ALL_PAGES) {
    const withoutRegistry = src.replaceAll('registry.veilproof.testnet', '');
    assert.ok(!withoutRegistry.includes('veilproof-demo.testnet'), `${name}: demo wallet address must not be hardcoded in the page`);
    assert.ok(!withoutRegistry.includes('veilproof.testnet'), `${name}: deployer wallet address must not be hardcoded in the page`);
    assert.ok(!src.includes('testnet-accounts'), `${name}: key file must never be referenced from the page`);
  }
});

test('prover flow: connect wallet sets the address, no address to type', () => {
  // The wallet you connect IS the wallet you prove: there is no
  // address field to type. The demo load sets the demo account
  // instead, for trying without a wallet. Ownership is proved only
  // by the connected wallet that owns the address being proved.
  assert.ok(proveHtml.includes('id="provingLine"'), 'prove.html must show the address being proved');
  assert.ok(!proveHtml.includes('id="previewAddress"'), 'prove.html must not have a preview address input');
  assert.ok(appJs.includes('readPreviewAddress'), 'app.js must read the proving address from state');
  assert.ok(appJs.includes('setProvingAddress'), 'app.js must set the proving address on connect or demo load');
  assert.ok(appJs.includes('previewMatchesConnected'), 'app.js must bind signing/publishing to the owning wallet');
  assert.ok(
    appJs.includes('if (!previewMatchesConnected())'),
    'publish() must refuse to sign when the connected wallet does not own the address being proved',
  );
  // The demo load and the snapshot fetch must not be gated on a wallet.
  assert.ok(!appJs.includes("$('loadDemoBtn').disabled = !connected"), 'demo load must not need a wallet');
  assert.ok(!appJs.includes("$('fetchSnapshotBtn').disabled = !connected"), 'snapshot fetch must not need a wallet');
  // The prover commitment, tripwire and disclosure must use the
  // address being proved, not the connected wallet id directly.
  // Since P2 the commitment is salted (fresh salt per report), so the
  // check is for commitAddress over the proving address.
  assert.ok(appJs.includes('commitAddress(state.previewAddress, proverSalt)'), 'prover commitment must hash the address being proved');
  assert.ok(appJs.includes('buildDisclosurePackage(report, state.previewAddress'), 'disclosure must use the address being proved');
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

test('both pages are responsive: viewport, scrollable tables, stacked proof table', () => {
  const css = readFileSync(new URL('../public/style.css', import.meta.url), 'utf8');
  const verifyHtml = readFileSync(new URL('../public/verify.html', import.meta.url), 'utf8');
  const demoJs = readFileSync(new URL('../public/demo.js', import.meta.url), 'utf8');
  // Viewport meta so phones scale the page instead of shrinking a
  // desktop layout.
  assert.ok(html.includes('width=device-width, initial-scale=1'), 'index.html must set the viewport');
  assert.ok(verifyHtml.includes('width=device-width, initial-scale=1'), 'verify.html must set the viewport');
  // Tables scroll inside their card instead of forcing the page wide.
  assert.ok(css.includes('.table-scroll'), 'style.css must define the table-scroll wrapper');
  assert.ok(css.includes('.table-scroll { overflow-x: auto'), 'table-scroll must scroll horizontally');
  for (const [name, src] of [['app.js', appJs], ['demo.js', demoJs], ['verify.html', verifyHtml]]) {
    assert.ok(src.includes('class="table-scroll"'), `${name} must wrap its tables in a table-scroll div`);
  }
  // The "what it proves" table stacks into cards on a phone, because
  // its first column is nowrap and would otherwise overflow.
  assert.ok(css.includes('.proves-table tr:first-child { display: none; }'), 'proves-table header must hide on small screens');
  assert.ok(css.includes('.proves-table tr { display: block;'), 'proves-table rows must stack on small screens');
  assert.ok(css.includes('.proves-table td:first-child { white-space: normal;'), 'proves-table claim cell must wrap on small screens');
  // Header wraps instead of overflowing on a narrow phone.
  assert.ok(css.includes('.site-header .wrap {') && css.includes('flex-wrap: wrap;'), 'site header must wrap');
  // Hero calls to action stack full-width on a phone for easy tapping.
  assert.ok(css.includes('.cta-row button, .cta-row .btn { flex: 1 1 100%;'), 'hero CTAs must go full-width on small screens');
});

test('demo.js renders the public predicate report, never an exact value', () => {
  const demoJs = readFileSync(new URL('../public/demo.js', import.meta.url), 'utf8');
  // The live demo report is predicate-only (P3): claims carry a
  // threshold, the score carries a band. Rendering esc(c.value) or
  // report.score.value would print "undefined" on the live site.
  assert.ok(!demoJs.includes('esc(c.value)'), 'demo must not render a claim value');
  assert.ok(!demoJs.includes('report.score.value +'), 'demo must not render a score value as a number');
  assert.ok(!demoJs.includes("c.points + ' / '"), 'demo must not render per-component points');
  assert.ok(demoJs.includes('<th>Claim</th><th>Passed</th><th>Threshold</th>'), 'demo claims table must be Claim / Passed / Threshold');
  assert.ok(demoJs.includes("band ' + esc(report.score.band)"), 'demo score must show the band when no value is present');
  // The Component / Max / Measured table moved out of demo.js into the
  // score panel built by verify-browser.js (and mirrored in verify.html).
});

test('score panel owns the Component / Max / Measured table', () => {
  const builder = readFileSync(new URL('../public/js/verify-browser.js', import.meta.url), 'utf8');
  const page = readFileSync(new URL('../public/verify.html', import.meta.url), 'utf8');
  assert.ok(builder.includes('<th>Component</th><th>Max</th><th>Measured</th>'), 'browser builder score table must be Component / Max / Measured');
  assert.ok(page.includes('<th>Component</th><th>Max</th><th>Measured</th>'), 'page builder score table must be Component / Max / Measured');
});
