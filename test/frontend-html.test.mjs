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

test('agent skill: linked from every page and named in the README', () => {
  // The skill is what lets an agent, including an AI judge, use
  // VeilProof. It is not enough for it to exist at /skill.md: it
  // must be linked from the site and named in the README, or no one
  // finds it. It sits at the top: in the header nav on every page,
  // and near the top of the README, not buried in the footer or in
  // the Judge section alone.
  const pages = ['index.html', 'prove.html', 'demo.html', 'verify.html', 'how-it-works.html'];
  for (const page of pages) {
    const html = readFileSync(new URL(`../public/${page}`, import.meta.url), 'utf8');
    assert.ok(html.includes('skill.md'), `${page} must link to the agent skill`);
    const nav = html.match(/<nav class="site-nav"[\s\S]*?<\/nav>/);
    assert.ok(nav && nav[0].includes('skill.md'), `${page} must link the skill from its top nav`);
  }
  const readme = readFileSync(new URL('../README.md', import.meta.url), 'utf8');
  assert.ok(readme.includes('skill.md'), 'README must name the agent skill');
  const top = readme.slice(0, readme.indexOf('## Privacy first'));
  assert.ok(top.includes('skill.md'), 'README must name the agent skill near the top');
  const skill = readFileSync(new URL('../public/skill.md', import.meta.url), 'utf8');
  assert.ok(skill.includes('For a judge'), 'skill.md must keep its section for a judge');
});

test('snapshot: a wallet with thousands of transactions still fetches in seconds', () => {
  // Verifying every transaction would take minutes for a busy wallet,
  // no matter how parallel it is. The snapshot verifies at most the
  // 100 most recent (the claims and the score only ever look at recent
  // transactions inside the policy windows), in parallel batches, and
  // caches block lookups so transactions in the same block do not each
  // pay for a block call. The auto-detect returns up to 100, newest
  // first, and the UI says how many older ones were capped.
  const onchainJs = readFileSync(new URL('../public/js/onchain.js', import.meta.url), 'utf8');
  assert.ok(onchainJs.includes('cappedTxCount'), 'onchain.js must track how many transactions were capped');
  assert.ok(onchainJs.includes('slice(0, 100)'), 'onchain.js must verify at most the 100 most recent transactions');
  assert.ok(onchainJs.includes('i += 12'), 'onchain.js must verify transactions in parallel batches of 12');
  assert.ok(onchainJs.includes('blockCache'), 'onchain.js must cache block lookups by block hash');
  assert.ok(onchainJs.includes('limit = 100'), 'fetchRecentTxHashes must return up to 100 recent transactions');
  assert.ok(appJs.includes('fetchRecentTxHashes(address, 100)'), 'app.js must ask the indexer for up to 100');
  assert.ok(appJs.includes('cappedTxCount'), 'app.js must tell the user how many transactions were capped');
});

test('prover flow: sampling window takes any number of days', () => {
  // The sampling window used to be a dropdown capped at 7 days. It
  // is now a free days input with no limit: type any number of days,
  // 0 or blank means no sampling. The sampling itself works in
  // hours, so the input converts days to hours.
  assert.ok(!proveHtml.includes('<select id="sampleWindow">'), 'prove.html must not cap sampling with a dropdown');
  assert.ok(proveHtml.includes('id="sampleWindow" type="text"'), 'prove.html must let the user type any number of days');
  assert.ok(appJs.includes('function sampleWindowHours'), 'app.js must convert the days input to hours');
  assert.ok(appJs.includes('days * 24'), 'app.js must convert days to hours for sampling');
  assert.ok(!appJs.includes('168'), 'app.js must not cap the sampling window at 7 days');
});

test('prover flow: a minimum without a window defaults to 30 days', () => {
  // The window fields show 30 as a placeholder, not a value. A user
  // who fills in a minimum and leaves the window blank used to get
  // "needs its window" and get stuck. readPolicy now defaults the
  // window to 30 and writes it back into the field, for all four
  // minimum-plus-window pairs.
  assert.ok(!appJs.includes('needs its window'), 'app.js must not fail on a missing window');
  assert.ok(appJs.includes("txWindow = '30'"), 'readPolicy must default the tx window to 30');
  assert.ok(appJs.includes("volWindow = '30'"), 'readPolicy must default the volume window to 30');
  assert.ok(appJs.includes("aggTxWindow = '30'"), 'readPolicy must default the aggregate tx window to 30');
  assert.ok(appJs.includes("aggVolWindow = '30'"), 'readPolicy must default the aggregate volume window to 30');
});

test('prover flow: signing the challenge fetches the snapshot automatically', () => {
  // Once the wallet is connected and the challenge is signed, the
  // snapshot is fetched for that wallet automatically: the user
  // should not have to tap Fetch snapshot by hand, and the snapshot
  // is always for the wallet they just signed.
  const signStart = appJs.indexOf('async function signChallenge');
  assert.ok(signStart >= 0, 'app.js must define signChallenge');
  const signEnd = appJs.indexOf('async function fetchSnapshot', signStart);
  const signBody = appJs.slice(signStart, signEnd >= 0 ? signEnd : undefined);
  assert.ok(signBody.includes('await fetchSnapshot()'), 'signChallenge must fetch the snapshot after signing');
  // Sustained and time-weighted claims need balance samples. If the
  // policy asks for them but the snapshot has none, Evaluate turns
  // sampling on (24 hours) and re-fetches instead of failing with
  // the claims-engine error about missing balanceSamples.
  assert.ok(appJs.includes("$('sampleWindow').value = '1'"), 'evaluate must turn sampling on when the policy needs samples');
  assert.ok(appJs.includes('Those claims need balance history sampling'), 'evaluate must say why it is re-fetching');
});

test('prover flow: connect wallet sets the address, no address to type', () => {
  // The wallet you connect IS the wallet you prove: there is no
  // address field to type, and no demo to load. Ownership is proved
  // only by the connected wallet that owns the address being proved.
  assert.ok(proveHtml.includes('id="provingLine"'), 'prove.html must show the address being proved');
  assert.ok(!proveHtml.includes('id="previewAddress"'), 'prove.html must not have a preview address input');
  assert.ok(!proveHtml.includes('id="loadDemoBtn"'), 'prove.html must not offer a demo to load');
  assert.ok(appJs.includes('readPreviewAddress'), 'app.js must read the proving address from state');
  assert.ok(appJs.includes('setProvingAddress'), 'app.js must set the proving address on connect');
  assert.ok(appJs.includes('previewMatchesConnected'), 'app.js must bind signing/publishing to the owning wallet');
  assert.ok(
    appJs.includes('if (!previewMatchesConnected())'),
    'publish() must refuse to sign when the connected wallet does not own the address being proved',
  );
  // The snapshot fetch button is never greyed out; clicking it
  // without a wallet says to connect one.
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
