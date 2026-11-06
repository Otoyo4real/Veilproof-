// VeilProof prover app — runs entirely in the prover's browser.
//
// Flow: paste a wallet address to preview (no wallet needed — the chain
// is public) -> connect the wallet that owns that address -> optional
// ownership challenge -> fetch onchain snapshot -> choose policy ->
// evaluate claims -> choose what to disclose -> optional NEAR AI
// analysis -> build report -> publish the three hashes onchain.
//
// The preview is read-only: anyone can read any wallet's onchain data,
// so a preview proves nothing about who you are. Ownership is proved
// only by the wallet: the challenge signature and the publish
// transaction must come from the wallet that owns the previewed
// address. previewMatchesConnected() enforces that binding at every
// step that needs it, and publish() refuses to sign otherwise.
//
// Privacy, by construction:
// - The snapshot, the address and the tx hashes never leave this
//   browser except as read-only NEAR RPC calls and the signed publish
//   transaction (which carries hashes only).
// - /api/analyze receives claim-level data only (claims, metrics,
//   policyVersion). The metrics are built here from an allowlist of
//   aggregate values; the address and tx hashes are never in the
//   request. The route and src/ai-analysis.js sanitise again.
// - The public report is checked with assertPublicReportClean before
//   it is shown or published: it must not contain the raw address or
//   any transaction hash.
//
// State is kept in sessionStorage so a wallet redirect (some wallets
// sign by redirecting away and back) does not lose the built report.

import { evaluateClaims } from './js/claims-engine.js';
import { computeScore } from './js/score.js';
import { buildReport, reportHash, evidenceHash, policyHash, newProverSalt, commitAddress } from './js/report.js';
import { buildDisclosurePackage, buildMultiDisclosurePackage, assertPublicReportClean } from './js/disclosure.js';
import { encryptDisclosurePackage, verifierKeyFingerprint } from './js/crypto-box.js';
import { fetchAccountSnapshot, dataHashForSnapshots } from './js/onchain.js';
import { sha256Hex, randomHex } from './js/crypto.js';
import { buildLinkMessage, verifyLinkSignature } from './js/nep413.js';

const NETWORK = 'testnet';
const REGISTRY = 'registry.veilproof.testnet';
const POLICY_VERSION = 'veilproof-policy-v2';
const RPC_URL = 'https://rpc.testnet.near.org';
const EXPLORER_TX = 'https://testnet.nearblocks.io/txns/';

// Publish cost: the registry charges storage at cost and refunds any
// excess deposit. A claim record is a few hundred bytes; at 1e19 yocto
// per byte that is roughly 0.003-0.005 NEAR. 0.01 NEAR attached covers
// it with margin and the excess comes back. Gas limit 100 TGas; only
// gas actually used is paid (typically a few thousandths of a NEAR on
// testnet). The wallet shows the exact figures before signing.
const PUBLISH_DEPOSIT_YOCTO = '10000000000000000000000'; // 0.01 NEAR
const PUBLISH_GAS = '100000000000000'; // 100 TGas

const $ = (id) => document.getElementById(id);
const esc = (s) =>
  String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');

// Decimal NEAR string -> yocto string, without floats.
function nearToYocto(str) {
  const m = /^(\d+)(?:\.(\d+))?$/.exec(String(str).trim());
  if (!m) throw new Error(`not a NEAR amount: ${JSON.stringify(str)}`);
  const frac = (m[2] || '').slice(0, 24).padEnd(24, '0');
  return (BigInt(m[1]) * 10n ** 24n + BigInt(frac || '0')).toString();
}

// Yocto string -> NEAR string with up to 6 decimals, trailing zeros cut.
function yoctoToNear(yocto) {
  const v = BigInt(yocto);
  const whole = v / 10n ** 24n;
  const frac = (v % 10n ** 24n).toString().padStart(24, '0').slice(0, 6).replace(/0+$/, '');
  return frac ? `${whole}.${frac}` : whole.toString();
}

function download(filename, obj) {
  const blob = new Blob([JSON.stringify(obj, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => {
    URL.revokeObjectURL(a.href);
    a.remove();
  }, 1000);
}

const state = {
  accountId: null,
  previewAddress: null,
  challenge: null,
  snapshot: null,
  linkedWallets: [],
  policy: null,
  evaluation: null,
  score: null,
  aiSummary: null,
  attestationRef: null,
  report: null,
  disclosurePackage: null,
  hashes: null,
};

function saveState() {
  try {
    sessionStorage.setItem(
      'veilproof-prover-state',
      JSON.stringify({
        accountId: state.accountId,
        previewAddress: state.previewAddress,
        challenge: state.challenge,
        snapshot: state.snapshot,
        suppliedTxCount: state.suppliedTxCount,
        linkedWallets: state.linkedWallets,
        policy: state.policy,
        evaluation: state.evaluation,
        score: state.score,
        aiSummary: state.aiSummary,
        attestationRef: state.attestationRef,
        report: state.report,
        disclosurePackage: state.disclosurePackage,
        hashes: state.hashes,
      }),
    );
  } catch (_) {
    // sessionStorage unavailable (private mode, etc.) — the flow still
    // works, only a wallet redirect would lose the built report.
  }
}

function loadState() {
  try {
    const raw = sessionStorage.getItem('veilproof-prover-state');
    if (!raw) return;
    const saved = JSON.parse(raw);
    Object.assign(state, saved);
  } catch (_) {
    // Corrupt or unavailable state: start fresh.
  }
}

// The address the prover is previewing. Reading is public, so this
// needs no wallet — but it proves nothing about ownership. The value
// is normalised to lowercase and validated as a NEAR account id:
// 2-64 chars of a-z, 0-9, '.', '_' or '-', ending in .near or
// .testnet, or a 64-hex implicit account.
function readPreviewAddress() {
  const raw = $('previewAddress').value.trim().toLowerCase();
  if (!raw) throw new Error('Enter a wallet address to preview (e.g. veilproof-demo.testnet).');
  const named = /^[a-z0-9._-]{2,64}$/.test(raw) && (raw.endsWith('.near') || raw.endsWith('.testnet'));
  const implicit = /^[0-9a-f]{64}$/.test(raw);
  if (!named && !implicit) {
    throw new Error(
      'That does not look like a NEAR address, use a named account ending in .near or .testnet, or a 64 character hex account.',
    );
  }
  state.previewAddress = raw;
  saveState();
  return raw;
}

// True only when the connected wallet is the wallet that owns the
// previewed address. This is the binding the whole proof rests on:
// the challenge signature and the publish transaction are only
// meaningful when the signer is the owner of the address in the
// report. Every step that signs or publishes checks this first.
function previewMatchesConnected() {
  return Boolean(state.previewAddress && state.accountId && state.previewAddress === state.accountId);
}

function refreshPublishBtn() {
  $('publishBtn').disabled = !(
    state.report &&
    $('publishConfirm').checked &&
    previewMatchesConnected()
  );
}

// Any upstream change invalidates the built report (and its hashes):
// the report must always be rebuilt from the current inputs before
// publishing. The UI says so plainly instead of silently reusing it.
function invalidateReport(note) {
  if (state.report) {
    state.report = null;
    state.disclosurePackage = null;
    state.hashes = null;
    $('reportOut').innerHTML =
      '<p class="warn">The inputs changed, ' + esc(note) + ' Rebuild the report before publishing.</p>';
    $('downloadReportBtn').disabled = true;
    $('downloadDisclosureBtn').disabled = true;
    $('publishBtn').disabled = true;
    $('publishCost').textContent = 'Build a report first, the cost preview appears here.';
    saveState();
  }
}

// --- Wallet (@fastnear/wallet 2.5.0, UMD global, same as Genesis) ---

function fastnear() {
  if (typeof window.nearWallet === 'undefined') {
    throw new Error('FastNear wallet library not loaded. Check the script tag.');
  }
  return window.nearWallet;
}

function currentAccountId(nw) {
  try {
    const id = nw.accountId({ network: NETWORK });
    return typeof id === 'string' && id ? id : null;
  } catch (_) {
    return null;
  }
}

function updateWalletUI() {
  $('connectBtn').textContent = state.accountId ? 'Disconnect wallet' : 'Connect wallet';
  $('accountLine').textContent = state.accountId ? `Connected: ${state.accountId} (testnet)` : '';
  $('walletStatus').textContent = state.accountId
    ? 'Connected on testnet. Ready to prove claims.'
    : 'Not connected. Meteor and MyNearWallet are supported.';
  const connected = Boolean(state.accountId);
  const matches = previewMatchesConnected();
  // Preview needs no wallet: the chain is public, so the demo load,
  // the snapshot fetch and the claims all work before any wallet is
  // connected. Only the steps that prove ownership need the wallet,
  // and they need the wallet that OWNS the previewed address.
  $('loadDemoBtn').disabled = false;
  $('fetchSnapshotBtn').disabled = false;
  $('challengeBtn').disabled = !(connected && matches);
  if (connected && !matches && !state.challenge) {
    $('challengeOut').innerHTML =
      '<p class="warn">Connected wallet <span class="mono">' + esc(state.accountId) + '</span> does not own the previewed address' +
      (state.previewAddress ? ' <span class="mono">' + esc(state.previewAddress) + '</span>' : '') +
      '. Switch wallets to sign the challenge for the previewed address, or preview a different address.</p>';
  }
  $('evaluateBtn').disabled = !state.snapshot;
  $('aiBtn').disabled = !state.evaluation;
  $('buildReportBtn').disabled = !state.evaluation;
  refreshPublishBtn();
}

async function connectWallet() {
  try {
    const nw = fastnear();
    if (state.accountId) {
      try {
        await nw.disconnect({ network: NETWORK });
      } catch (_) {}
      state.accountId = null;
      state.challenge = null;
      // The preview, snapshot, claims and report stay: they belong to
      // the previewed address, not to the wallet session, and the
      // report is still bound to that address. Only the ownership
      // proof (the challenge) is gone, and publish stays blocked until
      // the owning wallet is connected again (previewMatchesConnected).
      $('challengeOut').innerHTML = '';
      updateWalletUI();
      saveState();
      return;
    }
    $('walletStatus').textContent = 'Opening wallet selector…';
    const result = await nw.connect({ network: NETWORK });
    const id =
      (result && typeof result.accountId === 'string' && result.accountId) || currentAccountId(nw);
    if (typeof id !== 'string' || !id) {
      $('walletStatus').textContent = 'Could not determine the connected account. Try again.';
      return;
    }
    state.accountId = id;
    updateWalletUI();
    saveState();
  } catch (err) {
    $('walletStatus').textContent = 'Wallet error: ' + err.message;
  }
}

// --- Ownership challenge (demo step 2) ---

async function rpcViewAccessKeyList(accountId) {
  const res = await fetch(RPC_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 'veilproof-access-keys',
      method: 'query',
      params: { request_type: 'view_access_key_list', account_id: accountId, finality: 'final' },
    }),
  });
  const json = await res.json();
  if (json.error) throw new Error(json.error.message || json.error.name || 'RPC error');
  return json.result.keys || [];
}

async function signChallenge() {
  const out = $('challengeOut');
  try {
    const nw = fastnear();
    const nonceBytes = new Uint8Array(32);
    globalThis.crypto.getRandomValues(nonceBytes);
    let bin = '';
    nonceBytes.forEach((b) => {
      bin += String.fromCharCode(b);
    });
    const nonce = btoa(bin);
    const challengeId = randomHex(8);
    const message = [
      'VeilProof ownership challenge',
      `Account: ${state.accountId}`,
      `Challenge: ${challengeId}`,
      `Time: ${new Date().toISOString()}`,
    ].join('\n');
    out.innerHTML = '<p class="muted">Waiting for the wallet to sign…</p>';
    const result = await nw.signMessage({ message, recipient: REGISTRY, nonce });
    // The exact return shape varies by wallet; extract defensively and
    // show the raw result so nothing is hidden.
    const signature = result?.signature ?? result?.signedMessage?.signature ?? null;
    const publicKey = result?.publicKey ?? result?.signedMessage?.publicKey ?? null;
    state.challenge = { challengeId, message, nonce, signature, publicKey, raw: result ?? null };
    let keyCheck = 'Public key not returned by the wallet, could not check it against the account.';
    if (typeof publicKey === 'string' && publicKey) {
      try {
        const keys = await rpcViewAccessKeyList(state.accountId);
        const found = keys.some((k) => k.public_key === publicKey);
        keyCheck = found
          ? `Public key ${publicKey} IS one of the account's access keys, the signer controls this account.`
          : `Public key ${publicKey} is NOT among the account's access keys, do not trust this signature.`;
      } catch (err) {
        keyCheck = 'Could not fetch the account access keys to check the public key: ' + err.message;
      }
    }
    out.innerHTML =
      '<p class="ok">Challenge signed.</p>' +
      '<p class="mono">Challenge: ' + esc(challengeId) + '</p>' +
      '<p class="mono">Public key: ' + esc(publicKey || '(not returned)') + '</p>' +
      '<p class="mono">Signature: ' + esc(signature || '(not returned)') + '</p>' +
      '<p>' + esc(keyCheck) + '</p>' +
      '<p class="muted">Full cryptographic verification of the NEP 413 payload is not done here, ' +
      'the publish transaction in step 5 is the binding proof onchain (the registry records the signer as the claim owner).</p>';
    saveState();
  } catch (err) {
    out.innerHTML =
      '<p class="error">Challenge signing failed: ' + esc(err.message) + '</p>' +
      '<p class="muted">Some wallets do not support message signing. The flow continues, ' +
      'the publish transaction itself still proves ownership.</p>';
  }
}

// --- Snapshot (demo step 3) ---

function parseTxLines() {
  const lines = $('txHashes').value.split('\n').map((l) => l.trim()).filter(Boolean);
  const entries = [];
  for (const line of lines) {
    const parts = line.split(',').map((p) => p.trim());
    // A bare hash is assumed to belong to the previewed address — the
    // wallet is not needed to read it, only to prove it is yours.
    if (parts.length === 1) entries.push({ hash: parts[0], senderId: state.previewAddress });
    else if (parts.length === 2) entries.push({ hash: parts[0], senderId: parts[1] });
    else throw new Error(`bad tx line (expected "hash" or "hash,senderId"): ${line}`);
  }
  return entries;
}

async function loadDemoHistory() {
  try {
    const res = await fetch('./demo-history.json');
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const history = await res.json();
    // No wallet needed: the demo history is public testnet data. Fill
    // the preview address too, so the preview is one click.
    $('previewAddress').value = history.accountId;
    state.previewAddress = history.accountId;
    $('txHashes').value = history.transfers.map((t) => `${t.hash},${t.senderId}`).join('\n');
    $('snapshotOut').innerHTML =
      '<p class="ok">Demo history loaded: ' + history.transfers.length + ' transfers for <span class="mono">' +
      esc(history.accountId) + '</span>. Press "Fetch snapshot" to verify them onchain, no wallet needed.</p>';
    updateWalletUI();
    saveState();
  } catch (err) {
    $('snapshotOut').innerHTML = '<p class="error">Could not load the demo history: ' + esc(err.message) + '</p>';
  }
}

function parseLinkedAddresses() {
  const raw = $('linkedAddresses').value.split('\n').map((l) => l.trim().toLowerCase()).filter(Boolean);
  for (const addr of raw) {
    const named = /^[a-z0-9._-]{2,64}$/.test(addr) && (addr.endsWith('.near') || addr.endsWith('.testnet'));
    const implicit = /^[0-9a-f]{64}$/.test(addr);
    if (!named && !implicit) throw new Error(`Linked address does not look like a NEAR address: ${addr}`);
    if (addr === state.previewAddress) throw new Error(`Linked address ${addr} is the primary address, list it only once.`);
  }
  if (new Set(raw).size !== raw.length) throw new Error('Linked addresses contain a duplicate.');
  return raw;
}

// One line per linked wallet, same order; a blank line means that
// wallet will link by signature instead of by transfer (the user
// signs the link statement in the snapshot step). Fewer lines than
// addresses is fine (the rest are blanks); more is an error.
function parseLinkTxHashes(count) {
  const raw = $('linkedTxHashes').value.split('\n').map((l) => l.trim());
  if (raw.length > count) {
    throw new Error(`Expected at most ${count} link transfer hash(es), one per linked wallet, got ${raw.length}.`);
  }
  while (raw.length < count) raw.push('');
  return raw.map((h) => (h === '' ? null : h));
}

async function fetchSnapshot() {
  const out = $('snapshotOut');
  try {
    const address = readPreviewAddress();
    const entries = parseTxLines();
    const linkedAddresses = parseLinkedAddresses();
    const linkHashes = parseLinkTxHashes(linkedAddresses.length);
    const sampleHours = Number($('sampleWindow').value);
    const sampleOpts = sampleHours > 0 ? { balanceSamples: { windowHours: sampleHours, samples: 4 } } : {};
    out.innerHTML = '<p class="muted">Fetching account state for <span class="mono">' + esc(address) + '</span> and verifying ' + entries.length + ' transaction(s)…</p>';
    const snapshot = await fetchAccountSnapshot(address, entries, sampleOpts);
    state.snapshot = snapshot;
    state.suppliedTxCount = entries.length;
    // A signature link is tied to the (linked, primary) pair only, not
    // to a snapshot, so a previously signed one survives a re-fetch.
    const prevSignatures = {};
    for (const w of state.linkedWallets) {
      if (w.linkSignature) prevSignatures[w.address] = w.linkSignature;
    }
    state.linkedWallets = [];
    // Linked wallets: their txs are the link transfer plus any tx
    // lines in the box whose sender is that wallet. Ownership is
    // proved either by the link transfer (a successful transfer to
    // the primary address) or by a signature over the link statement
    // — the signature route costs no gas and leaves no public
    // onchain record connecting the wallets. A wallet with neither
    // is kept and offered a "Sign link" button below.
    // Balance samples for linked wallets reuse the PRIMARY snapshot's
    // exact sample heights: the sustained/time-weighted claims refuse
    // to run when wallets were sampled at different heights, and two
    // sequential "current height" reads would drift apart by a block.
    const linkedSampleOpts =
      sampleHours > 0 && snapshot.balanceSamples
        ? { balanceSamples: { windowHours: sampleHours, samples: 4, heights: snapshot.balanceSamples.map((s) => s.blockHeight) } }
        : sampleOpts;
    for (let i = 0; i < linkedAddresses.length; i += 1) {
      const linkedAddress = linkedAddresses[i];
      const linkTxHash = linkHashes[i];
      const walletEntries = entries.filter((e) => e.senderId === linkedAddress);
      if (linkTxHash && !walletEntries.some((e) => e.hash === linkTxHash)) {
        walletEntries.push({ hash: linkTxHash, senderId: linkedAddress });
      }
      const linkedSnapshot = await fetchAccountSnapshot(linkedAddress, walletEntries, linkedSampleOpts);
      if (linkTxHash) {
        const linkTx = linkedSnapshot.txs.find((t) => t.hash === linkTxHash);
        if (!linkTx || linkTx.senderId !== linkedAddress || linkTx.receiverId !== address || linkTx.status !== 'Success') {
          throw new Error(`Link transfer for ${linkedAddress} did not verify as a successful transfer to ${address}.`);
        }
        state.linkedWallets.push({ address: linkedAddress, snapshot: linkedSnapshot, linkTxHash });
      } else if (prevSignatures[linkedAddress]) {
        state.linkedWallets.push({ address: linkedAddress, snapshot: linkedSnapshot, linkSignature: prevSignatures[linkedAddress] });
      } else {
        state.linkedWallets.push({ address: linkedAddress, snapshot: linkedSnapshot });
      }
    }
    invalidateReport('a new snapshot was fetched.');
    renderSnapshot(snapshot, address, entries.length, sampleHours);
    updateWalletUI();
    saveState();
  } catch (err) {
    out.innerHTML = '<p class="error">Snapshot failed: ' + esc(err.message) + '</p>';
  }
}

// Render the fetched snapshot, including the linked-wallet status and
// a Sign link button for each wallet that still needs a link proof.
// Re-run after a link is signed so the status line reflects it.
function renderSnapshot(snapshot, address, entriesCount, sampleHours) {
  const out = $('snapshotOut');
  const linkedLine = state.linkedWallets.length > 0
    ? '<p>Linked wallets: ' + state.linkedWallets.map((w) => {
        const method = w.linkTxHash ? 'proved by transfer' : w.linkSignature ? 'proved by signature' : 'needs a link signature';
        return '<span class="mono">' + esc(w.address) + '</span> (' + method + ')';
      }).join(', ') + '.</p>' +
      (state.linkedWallets.some((w) => !w.linkTxHash && !w.linkSignature)
        ? '<p>For each wallet above that still needs a link: switch to that wallet in your wallet app, then press its Sign link button. No transfer, no gas, the signature is the proof.</p>' +
          state.linkedWallets.map((w, i) => (!w.linkTxHash && !w.linkSignature
            ? '<p><button type="button" data-sign-link="' + i + '">Sign link for ' + esc(w.address) + '</button> <span data-sign-link-out="' + i + '"></span></p>'
            : '')).join('')
        : '')
    : '';
  const sampleLine = snapshot.balanceSamples
    ? '<p>Balance samples: ' + snapshot.balanceSamples.length + ' readings over ' + sampleHours + 'h (lowest ' + esc(yoctoToNear(snapshot.balanceSamples.reduce((m, s) => (BigInt(s.amount) < BigInt(m) ? s.amount : m), snapshot.balanceSamples[0].amount))) + ' NEAR).</p>'
    : '';
  out.innerHTML =
    '<p class="ok">Snapshot fetched for <span class="mono">' + esc(address) + '</span> at block ' + snapshot.blockHeight + '.</p>' +
    '<p>Balance: <span class="mono">' + esc(yoctoToNear(snapshot.account.amount)) + ' NEAR</span> ' +
    '(staked: <span class="mono">' + esc(yoctoToNear(snapshot.account.locked)) + ' NEAR</span>)</p>' +
    '<p>Verified transactions: ' + snapshot.txs.length + ' of ' + entriesCount + ' supplied ' +
    '(unverifiable hashes are skipped).</p>' +
    linkedLine + sampleLine +
    '<p>Data hash: <span class="mono">' + esc(snapshot.dataHash) + '</span></p>';
  out.querySelectorAll('[data-sign-link]').forEach((btn) => {
    btn.addEventListener('click', () => signLink(Number(btn.getAttribute('data-sign-link'))));
  });
}

// Sign the link statement for one linked wallet (no transfer, no gas).
// The user switches to that wallet in their wallet app first — the
// wallet signs the statement, and the app checks the signature twice:
// the returned public key must be one of the linked account's access
// keys, and the NEP-413 signature must verify against that key.
async function signLink(index) {
  const entry = state.linkedWallets[index];
  const outSpan = document.querySelector(`[data-sign-link-out="${index}"]`);
  if (!entry) return;
  const setOut = (html) => { if (outSpan) outSpan.innerHTML = html; };
  try {
    const nw = fastnear();
    const nonceBytes = new Uint8Array(32);
    globalThis.crypto.getRandomValues(nonceBytes);
    let bin = '';
    nonceBytes.forEach((b) => { bin += String.fromCharCode(b); });
    const nonce = btoa(bin);
    const message = buildLinkMessage(entry.address, state.previewAddress);
    setOut('<span class="muted">Waiting for the wallet to sign… (switch to ' + esc(entry.address) + ' in your wallet app first.)</span>');
    const result = await nw.signMessage({ message, recipient: REGISTRY, nonce });
    const signature = result?.signature ?? result?.signedMessage?.signature ?? null;
    const publicKey = result?.publicKey ?? result?.signedMessage?.publicKey ?? null;
    if (!signature || !publicKey) {
      setOut('<span class="error">The wallet did not return a signature and public key, the link was not proved.</span>');
      return;
    }
    const keys = await rpcViewAccessKeyList(entry.address);
    if (!keys.some((k) => k.public_key === publicKey)) {
      setOut('<span class="error">Public key ' + esc(publicKey) + ' is NOT one of ' + esc(entry.address) + ' access keys, the link was not proved. Switch to that wallet and try again.</span>');
      return;
    }
    const linkSignature = { message, nonce, recipient: REGISTRY, signature, publicKey };
    if (!(await verifyLinkSignature(linkSignature))) {
      setOut('<span class="error">The signature did not verify, the link was not proved.</span>');
      return;
    }
    entry.linkSignature = linkSignature;
    invalidateReport('a link was signed.');
    saveState();
    renderSnapshot(state.snapshot, state.previewAddress, state.suppliedTxCount ?? state.snapshot.txs.length, Number($('sampleWindow').value));
    updateWalletUI();
  } catch (err) {
    setOut('<span class="error">Link signing failed: ' + esc(err.message) + '</span>');
  }
}

// --- Policy + claims (demo step 4) ---

function readPolicy() {
  const policy = {};
  const balance = $('polBalance').value.trim();
  if (balance) policy.balanceAtLeastYocto = nearToYocto(balance);
  const staked = $('polStaked').value.trim();
  if (staked) policy.stakedAtLeastYocto = nearToYocto(staked);
  const minTx = $('polMinTx').value.trim();
  const txWindow = $('polTxWindow').value.trim();
  if (minTx) {
    if (!/^\d+$/.test(minTx)) throw new Error('Minimum tx count must be a whole number.');
    if (!txWindow) throw new Error('A minimum tx count needs its window (days).');
    policy.minTxCount = minTx;
    policy.txWindowDays = Number(txWindow);
  } else if (txWindow) {
    policy.txWindowDays = Number(txWindow);
  }
  const minVol = $('polMinVol').value.trim();
  const volWindow = $('polVolWindow').value.trim();
  if (minVol) {
    if (!volWindow) throw new Error('A minimum volume needs its window (days).');
    policy.minVolumeYocto = nearToYocto(minVol);
    policy.volumeWindowDays = Number(volWindow);
  } else if (volWindow) {
    policy.volumeWindowDays = Number(volWindow);
  }
  const noFailed = $('polNoFailed').value.trim();
  if (noFailed) {
    if (!/^\d+$/.test(noFailed)) throw new Error('No failed window must be a whole number of days.');
    policy.noFailedWindowDays = Number(noFailed);
  }
  const aggBalance = $('polAggBalance').value.trim();
  if (aggBalance) policy.aggregateBalanceAtLeastYocto = nearToYocto(aggBalance);
  const aggMinTx = $('polAggMinTx').value.trim();
  const aggTxWindow = $('polAggTxWindow').value.trim();
  if (aggMinTx) {
    if (!/^\d+$/.test(aggMinTx)) throw new Error('Aggregate minimum tx count must be a whole number.');
    if (!aggTxWindow) throw new Error('An aggregate minimum tx count needs its window (days).');
    policy.aggregateMinTxCount = aggMinTx;
    policy.aggregateTxWindowDays = Number(aggTxWindow);
  } else if (aggTxWindow) {
    policy.aggregateTxWindowDays = Number(aggTxWindow);
  }
  const aggMinVol = $('polAggMinVol').value.trim();
  const aggVolWindow = $('polAggVolWindow').value.trim();
  if (aggMinVol) {
    if (!aggVolWindow) throw new Error('An aggregate minimum volume needs its window (days).');
    policy.aggregateMinVolumeYocto = nearToYocto(aggMinVol);
    policy.aggregateVolumeWindowDays = Number(aggVolWindow);
  } else if (aggVolWindow) {
    policy.aggregateVolumeWindowDays = Number(aggVolWindow);
  }
  const sustained = $('polSustained').value.trim();
  if (sustained) policy.sustainedBalanceAtLeastYocto = nearToYocto(sustained);
  const timeWeighted = $('polTimeWeighted').value.trim();
  if (timeWeighted) policy.timeWeightedBalanceAtLeastYocto = nearToYocto(timeWeighted);
  for (const [key, value] of Object.entries(policy)) {
    if (typeof value === 'number' && (!Number.isInteger(value) || value < 0)) {
      throw new Error(`Policy field ${key} must be a non-negative whole number of days.`);
    }
  }
  return policy;
}

function renderClaims() {
  const { claims, allPassed } = state.evaluation;
  $('claimsOut').innerHTML =
    '<p class="' + (allPassed ? 'ok' : 'error') + '">' +
    (allPassed ? 'All claims pass.' : 'Some claims do not pass, they can still be published as failing claims.') +
    '</p>' +
    '<div class="table-scroll"><table><tr><th>Claim</th><th>Passed</th><th>Value</th><th>Threshold</th></tr>' +
    claims
      .map(
        (c) =>
          '<tr><td>' + esc(c.id) + '</td><td>' + (c.passed ? 'yes' : 'NO') + '</td><td class="mono">' +
          esc(c.value) + '</td><td class="mono">' + esc(c.threshold) + '</td></tr>',
      )
      .join('') +
    '</table></div>';
  $('discloseList').innerHTML =
    '<p><strong>Disclose in the public report:</strong></p>' +
    claims
      .map(
        (c) =>
          '<label><input type="checkbox" data-claim="' + esc(c.id) + '" checked style="width:auto"> ' +
          esc(c.id) + ', ' + (c.passed ? 'passed' : 'did not pass') + '</label>',
      )
      .join('');
  const score = state.score;
  $('scoreOut').innerHTML = score
    ? '<h3>Portable credit score (' + esc(score.version) + ')</h3>' +
      '<p><strong>' + score.value + ' / 1000, ' + esc(score.band) + '</strong></p>' +
      '<p class="muted">Deterministic and recomputable: any app holding the disclosure package can rerun the same published rules and get this exact number. That is what makes it reusable across apps.</p>' +
      '<div class="table-scroll"><table><tr><th>Component</th><th>Points</th><th>Measured</th></tr>' +
      score.components
        .map((c) => '<tr><td>' + esc(c.label) + '</td><td>' + c.points + ' / ' + c.max + '</td><td>' + (c.measured ? 'yes' : 'not measured') + '</td></tr>')
        .join('') +
      '</table></div>'
    : '';
  updateWalletUI();
}

function evaluate() {
  try {
    if (!state.snapshot) throw new Error('Fetch a snapshot first.');
    const policy = readPolicy();
    if (Object.keys(policy).length === 0) throw new Error('Set at least one policy field.');
    const nowNs = (BigInt(Date.now()) * 1000000n).toString();
    state.policy = policy;
    const bundle = { wallets: [state.snapshot, ...state.linkedWallets.map((w) => w.snapshot)] };
    state.evaluation = evaluateClaims(bundle, policy, nowNs);
    // The score is computed from the same snapshots and the policy's
    // windows, so any verifier re-running it gets the same number.
    state.score = computeScore(bundle, {
      txWindowDays: policy.txWindowDays,
      volumeWindowDays: policy.volumeWindowDays,
      noFailedWindowDays: policy.noFailedWindowDays,
    }, nowNs);
    // A new evaluation supersedes any AI summary: the summary was about
    // the old claims. The prover can re-run the analysis.
    state.aiSummary = null;
    state.attestationRef = null;
    $('aiStatus').textContent = 'AI underwriting not run yet for these claims. The report will say "not analysed" unless you run it.';
    invalidateReport('the claims were reevaluated.');
    renderClaims();
    saveState();
  } catch (err) {
    $('claimsOut').innerHTML = '<p class="error">Evaluation failed: ' + esc(err.message) + '</p>';
    $('scoreOut').innerHTML = '';
  }
}

// --- AI analysis (demo steps 5-6) ---

function buildMetrics() {
  const snapshots = [state.snapshot, ...state.linkedWallets.map((w) => w.snapshot)];
  const policy = state.policy;
  const ids = new Set(snapshots.map((s) => s.account.accountId));
  let balance = 0n;
  let staked = 0n;
  let success = 0;
  let failed = 0;
  let volume = 0n;
  const seen = new Set();
  for (const snap of snapshots) {
    balance += BigInt(snap.account.amount);
    staked += BigInt(snap.account.locked);
    for (const tx of snap.txs) {
      if (seen.has(tx.hash)) continue;
      seen.add(tx.hash);
      if (tx.status === 'Success') {
        success += 1;
        if (ids.has(tx.senderId) || ids.has(tx.receiverId)) {
          volume += BigInt(tx.amountYocto);
        }
      } else if (tx.status === 'Failure') {
        failed += 1;
      }
    }
  }
  // Allowlist by construction: only aggregate values, never the address,
  // never tx hashes, never the snapshot.
  return {
    balanceYocto: balance.toString(),
    stakedYocto: staked.toString(),
    txCount: seen.size,
    successTxCount: success,
    failedTxCount: failed,
    volumeYocto: volume.toString(),
    windowDays: policy.txWindowDays ?? policy.volumeWindowDays ?? policy.noFailedWindowDays ?? 30,
    txWindowDays: policy.txWindowDays,
    volumeWindowDays: policy.volumeWindowDays,
    noFailedWindowDays: policy.noFailedWindowDays,
  };
}

async function runAiAnalysis() {
  const status = $('aiStatus');
  try {
    if (!state.evaluation) throw new Error('Evaluate the claims first.');
    status.textContent = 'Asking NEAR AI Cloud for an underwriting judgment…';
    const res = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        mode: 'underwriting',
        claims: state.evaluation.claims,
        metrics: buildMetrics(),
        score: state.score,
        policyVersion: POLICY_VERSION,
      }),
    });
    const body = await res.json();
    if (!res.ok) {
      status.textContent = 'AI underwriting failed: ' + (body.error || `HTTP ${res.status}`) + '. The report will say "not analysed".';
      return;
    }
    if (body.status === 'not_configured') {
      status.textContent =
        'AI underwriting not available yet, the separate VeilProof NEAR AI key is not set on the server. ' +
        'The report will say "not analysed", which is honest, not a failure.';
      state.aiSummary = null;
      state.attestationRef = null;
    } else if (body.status === 'ok' && body.summary) {
      state.aiSummary = body.summary;
      state.attestationRef = body.summary.attestation?.ref ?? null;
      const limit = body.summary.suggestedLimitNear === null || body.summary.suggestedLimitNear === undefined
        ? 'no amount suggested'
        : 'suggested limit ' + esc(String(body.summary.suggestedLimitNear)) + ' NEAR';
      status.innerHTML =
        '<span class="ok">Underwriting judgment complete (advisory, not a guarantee).</span> Verdict: <strong>' +
        esc(body.summary.verdict) + '</strong> (' + limit + ', confidence ' + esc(body.summary.confidence) + '). ' +
        'Attestation: ' + (body.summary.attestation?.verifiable ? 'verified (nonce matched)' : 'unattested') + '.';
      invalidateReport('the AI underwriting was added.');
    } else {
      status.textContent =
        'AI underwriting returned status "' + body.status + '"' +
        (body.error ? ` (${body.error})` : '') +
        '. The report will say "not analysed".';
      state.aiSummary = null;
      state.attestationRef = null;
    }
    saveState();
  } catch (err) {
    status.textContent = 'AI underwriting failed: ' + err.message + '. The report will say "not analysed".';
  }
}

// --- Report (demo step 7) ---

// The contract's expires_at is a u64 nanosecond timestamp, and the
// wallet passes it as a JSON number. JS numbers cannot hold every
// 64-bit integer exactly, so the expiry is rounded DOWN to a whole
// second (a multiple of 10^9 ns). Whole seconds are exactly
// representable as doubles at current timestamps, and the exactness is
// asserted before publishing. The report carries this same rounded
// value, so the report and the onchain record agree exactly.
// NOTE: the old code rounded to 1024 ns and asserted with
// BigInt(Number(x).toString()). That check goes through the double's
// shortest decimal string, which drops low digits at current
// timestamps (e.g. ...9808 becomes "...9800"), so it threw on every
// real report build. The check below compares the double's exact value
// instead, and the demo script uses the same whole-second alignment
// (scripts/demo-e2e.mjs).
function computeExpiresAt(days) {
  const nowNs = BigInt(Date.now()) * 1000000n;
  const expires = nowNs + BigInt(days) * 86400n * 1000000000n;
  const aligned = expires - (expires % 1000000000n);
  if (BigInt(Number(aligned)) !== aligned) {
    throw new Error('expiry timestamp is not exactly representable as a JSON number, refusing to publish');
  }
  return aligned.toString();
}

async function buildReportAndHashes() {
  const out = $('reportOut');
  try {
    if (!state.evaluation || !state.snapshot) throw new Error('Evaluate the claims first.');
    if (!state.previewAddress) throw new Error('Enter a wallet address to preview first.');
    const disclosed = Array.from(document.querySelectorAll('#discloseList input[type="checkbox"]:checked')).map(
      (box) => box.dataset.claim,
    );
    const days = Number($('expirySelect').value);
    const expiresAt = computeExpiresAt(days);
    // P2 unlinkability: a fresh random salt per report (and per linked
    // wallet), so two reports from the same treasury get different
    // commitments and cannot be matched from public data. The salts
    // travel only inside the disclosure package, never in the report.
    const proverSalt = newProverSalt();
    const proverAddressHash = await commitAddress(state.previewAddress, proverSalt);
    const linkedSalts = state.linkedWallets.map(() => newProverSalt());
    const linkedProverHashes = [];
    for (let i = 0; i < state.linkedWallets.length; i += 1) {
      linkedProverHashes.push(await commitAddress(state.linkedWallets[i].address, linkedSalts[i]));
    }
    // The evidence data hash covers every wallet in the bundle (and
    // any balance samples); the single-wallet hash is only used when
    // there is one wallet and no samples.
    const dataHash = await dataHashForSnapshots([state.snapshot, ...state.linkedWallets.map((w) => w.snapshot)]);
    const report = buildReport({
      proverAddressHash,
      claims: state.evaluation.claims,
      policyVersion: POLICY_VERSION,
      aiSummary: state.aiSummary,
      evidenceRefs: { dataHash, attestationRef: state.attestationRef },
      expiresAt,
      disclosedFields: disclosed,
      linkedProverHashes,
      score: state.score,
    });
    // Tripwire: the public report must not contain any raw address, any
    // transaction hash, or any prover salt. If it ever did, refuse to
    // show or publish it.
    const allAddresses = [state.previewAddress, ...state.linkedWallets.map((w) => w.address)];
    const allTxHashes = [state.snapshot, ...state.linkedWallets.map((w) => w.snapshot)].flatMap((s) => s.txs.map((t) => t.hash));
    const allSalts = [proverSalt, ...linkedSalts];
    for (const addr of allAddresses) assertPublicReportClean(report, addr, allTxHashes, allSalts);
    const disclosurePackage =
      state.linkedWallets.length > 0
        ? await buildMultiDisclosurePackage(
            report,
            state.previewAddress,
            state.snapshot,
            state.linkedWallets.map((w, i) => ({ ...w, salt: linkedSalts[i] })),
            proverSalt,
          )
        : await buildDisclosurePackage(report, state.previewAddress, state.snapshot, proverSalt);
    const hashes = {
      report_hash: await reportHash(report),
      evidence_hash: await evidenceHash(report.evidenceRefs),
      policy_hash: await policyHash(report.policyVersion, state.policy),
    };
    state.report = report;
    state.disclosurePackage = disclosurePackage;
    state.hashes = hashes;
    out.innerHTML =
      '<p class="ok">Report built. Clean check passed, the report contains no address and no transaction hash.</p>' +
      '<p>Report ID: <span class="mono">' + esc(report.reportId) + '</span></p>' +
      '<p>Prover commitment (salted SHA 256 of the address, fresh salt per report, so two reports from the same treasury cannot be matched; the address itself is never shown):<br><span class="mono">' +
      esc(report.prover) + '</span></p>' +
      (report.linkedProvers.length > 0 ? '<p>Linked wallets: ' + report.linkedProvers.length + ' (commitments only).</p>' : '') +
      (report.score
        ? '<p>Credit score: <strong>' + state.score.value + ' / 1000 (' + esc(report.score.band) + ')</strong>, your exact score; the public report carries only the band, recomputable by any app from the disclosure package.</p>'
        : '<p>Credit score: not scored.</p>') +
      '<p>AI summary: ' + (report.aiSummary === null ? 'Not analysed.' : esc(report.aiSummary.verdict ?? report.aiSummary.role ?? 'analysed') + ' (NEAR AI Cloud, advisory).') + '</p>' +
      '<p>Report hash: <span class="mono">' + esc(hashes.report_hash) + '</span></p>' +
      '<p>Evidence hash: <span class="mono">' + esc(hashes.evidence_hash) + '</span></p>' +
      '<p>Policy hash: <span class="mono">' + esc(hashes.policy_hash) + '</span></p>' +
      '<pre>' + esc(JSON.stringify(report, null, 2)) + '</pre>';
    $('downloadReportBtn').disabled = false;
    $('downloadDisclosureBtn').disabled = false;
    $('encryptDisclosureBtn').disabled = false;
    $('downloadEncryptedBtn').disabled = true;
    state.encryptedDisclosurePackage = null;
    $('encryptOut').innerHTML = '';
    $('publishCost').innerHTML =
      'Publishing attaches <strong>0.01 NEAR</strong> and a 100 TGas gas limit. ' +
      'The contract charges storage at cost (roughly 0.003 to 0.005 NEAR for a claim record) and refunds the excess deposit; ' +
      'you pay only for gas actually used. The wallet shows the exact amounts before you sign.';
    $('publishBtn').disabled = !$('publishConfirm').checked;
    refreshPublishBtn();
    saveState();
  } catch (err) {
    out.innerHTML = '<p class="error">Report build failed: ' + esc(err.message) + '</p>';
  }
}

// --- Verifier-bound disclosure (P4) ---
// Seal the disclosure package for ONE verifier: only the holder of
// that verifier's Curve25519 secret key can open it, and it expires
// with the report. The sealed package is downloaded, never shown
// on the page (it is ciphertext).
async function encryptDisclosureForVerifier() {
  const out = $('encryptOut');
  try {
    if (!state.report || !state.disclosurePackage) throw new Error('Build a report first.');
    const key = $('verifierKeyInput').value.trim();
    if (!key) throw new Error('Paste the verifier\'s encryption public key (base64) first.');
    const encrypted = await encryptDisclosurePackage(state.disclosurePackage, key, state.report.expiresAt);
    state.encryptedDisclosurePackage = encrypted;
    const fingerprint = (await verifierKeyFingerprint(key)).slice(0, 16);
    out.innerHTML =
      '<p class="ok">Sealed for verifier key ' + esc(fingerprint) + '…, only that verifier can open it.</p>' +
      '<p>Expires with the report: <span class="mono">' +
      esc(new Date(Number(BigInt(state.report.expiresAt) / 1000000n)).toISOString()) + '</span></p>';
    $('downloadEncryptedBtn').disabled = false;
    saveState();
  } catch (err) {
    out.innerHTML = '<p class="err">Could not seal the disclosure package: ' + esc(err.message) + '</p>';
  }
}

// --- Publish (demo step 8) ---

function extractTxHash(result) {
  if (!result || typeof result !== 'object') return null;
  if (result.transaction && typeof result.transaction.hash === 'string') return result.transaction.hash;
  if (typeof result.transactionHash === 'string') return result.transactionHash;
  if (typeof result.hash === 'string') return result.hash;
  if (Array.isArray(result.transactionHashes) && result.transactionHashes[0]) return result.transactionHashes[0];
  return null;
}

async function publish() {
  const out = $('publishOut');
  try {
    if (!state.report || !state.hashes) throw new Error('Build a report first.');
    if (!$('publishConfirm').checked) throw new Error('Tick the confirmation box first.');
    // The binding: the publish transaction is signed by the connected
    // wallet, and the registry records the signer as the claim owner.
    // If the signer is not the owner of the previewed address, the
    // report would claim one wallet's history under another wallet's
    // name — so refuse to sign at all, rather than publish a lie.
    if (!previewMatchesConnected()) {
      throw new Error(
        'Connect the wallet that owns ' + (state.previewAddress || 'the previewed address') +
          ' before publishing, the connected wallet ' + (state.accountId || '(none)') + ' does not own it.',
      );
    }
    const nw = fastnear();
    out.innerHTML = '<p class="muted">Waiting for the wallet to sign the publish transaction…</p>';
    const result = await nw.sendTransaction({
      receiverId: REGISTRY,
      network: NETWORK,
      actions: [
        {
          type: 'FunctionCall',
          methodName: 'publish_claim',
          args: {
            claim_id: state.report.reportId,
            report_hash: state.hashes.report_hash,
            evidence_hash: state.hashes.evidence_hash,
            policy_hash: state.hashes.policy_hash,
            // u64 as a JSON number: exactly representable by construction
            // (see computeExpiresAt).
            expires_at: Number(state.report.expiresAt),
          },
          gas: PUBLISH_GAS,
          deposit: PUBLISH_DEPOSIT_YOCTO,
        },
      ],
    });
    const txHash = extractTxHash(result);
    if (txHash) {
      out.innerHTML =
        '<p class="ok">Published onchain.</p>' +
        '<p>Transaction: <a href="' + EXPLORER_TX + encodeURIComponent(txHash) + '" target="_blank" rel="noopener"><span class="mono">' +
        esc(txHash) + '</span></a></p>' +
        '<p>Report ID: <span class="mono">' + esc(state.report.reportId) + '</span></p>' +
        '<p>Give the report JSON to your verifier, and the disclosure package privately. ' +
        'They can check it at <a href="verify.html">the verifier portal</a> using the report ID above.</p>';
    } else {
      out.innerHTML =
        '<p class="ok">The wallet returned without a readable transaction hash, the transaction may still have been submitted. Check the wallet activity or the registry directly.</p>' +
        '<pre>' + esc(JSON.stringify(result ?? null, null, 2)) + '</pre>';
    }
    saveState();
  } catch (err) {
    out.innerHTML = '<p class="error">Publish failed: ' + esc(err.message) + '</p>';
  }
}

// --- Restore after a wallet redirect ---

function handleRedirectResult() {
  const params = new URLSearchParams(window.location.search);
  const hashes = params.get('transactionHashes');
  if (!hashes) return;
  const first = hashes.split(',')[0];
  window.history.replaceState({}, '', window.location.pathname);
  if (state.report) {
    $('publishOut').innerHTML =
      '<p class="ok">Published onchain (returned from the wallet).</p>' +
      '<p>Transaction: <a href="' + EXPLORER_TX + encodeURIComponent(first) + '" target="_blank" rel="noopener"><span class="mono">' +
      esc(first) + '</span></a></p>' +
      '<p>Report ID: <span class="mono">' + esc(state.report.reportId) + '</span></p>';
  }
}

function restoreUIFromState() {
  if (state.previewAddress) $('previewAddress').value = state.previewAddress;
  if (state.accountId) updateWalletUI();
  if (state.challenge) {
    $('challengeOut').innerHTML =
      '<p class="muted">Challenge signed earlier this session (challenge ' + esc(state.challenge.challengeId) + ').</p>';
  }
  if (state.snapshot) {
    $('snapshotOut').innerHTML =
      '<p class="ok">Snapshot restored from this session (block ' + state.snapshot.blockHeight + ', ' +
      state.snapshot.txs.length + ' verified txs).</p>' +
      '<p>Balance: <span class="mono">' + esc(yoctoToNear(state.snapshot.account.amount)) + ' NEAR</span></p>' +
      '<p>Data hash: <span class="mono">' + esc(state.snapshot.dataHash) + '</span></p>';
  }
  if (state.evaluation) renderClaims();
  if (state.aiSummary) {
    $('aiStatus').innerHTML =
      '<span class="ok">AI analysis complete.</span> Verdict: <strong>' + esc(state.aiSummary.verdict) + '</strong>.';
  }
  if (state.report && state.hashes) {
    $('reportOut').innerHTML =
      '<p class="ok">Report restored from this session.</p>' +
      '<p>Report ID: <span class="mono">' + esc(state.report.reportId) + '</span></p>' +
      '<pre>' + esc(JSON.stringify(state.report, null, 2)) + '</pre>';
    $('downloadReportBtn').disabled = false;
    $('downloadDisclosureBtn').disabled = false;
    $('encryptDisclosureBtn').disabled = !state.disclosurePackage;
    $('downloadEncryptedBtn').disabled = true;
    state.encryptedDisclosurePackage = null;
    $('publishCost').innerHTML =
      'Publishing attaches <strong>0.01 NEAR</strong> and a 100 TGas gas limit. ' +
      'The contract charges storage at cost and refunds the excess deposit. The wallet shows the exact amounts before you sign.';
    $('publishBtn').disabled = !$('publishConfirm').checked;
    refreshPublishBtn();
  }
  updateWalletUI();
}

window.addEventListener('load', async () => {
  loadState();
  restoreUIFromState();
  handleRedirectResult();
  $('connectBtn').addEventListener('click', connectWallet);
  $('challengeBtn').addEventListener('click', signChallenge);
  $('loadDemoBtn').addEventListener('click', loadDemoHistory);
  $('fetchSnapshotBtn').addEventListener('click', fetchSnapshot);
  $('previewAddress').addEventListener('change', () => {
    const next = $('previewAddress').value.trim().toLowerCase();
    // A new address means a new snapshot: everything downstream was
    // about the old address and must go, so a stale report can never
    // be published under a new address.
    if (state.snapshot && state.snapshot.account.accountId !== next) {
      state.snapshot = null;
      state.policy = null;
      state.evaluation = null;
      state.aiSummary = null;
      state.attestationRef = null;
      invalidateReport('the previewed address changed.');
      $('snapshotOut').innerHTML = '';
      $('claimsOut').innerHTML = '';
      $('discloseList').innerHTML = '';
      updateWalletUI();
    }
    state.previewAddress = next || null;
    saveState();
  });
  $('evaluateBtn').addEventListener('click', evaluate);
  $('aiBtn').addEventListener('click', runAiAnalysis);
  $('buildReportBtn').addEventListener('click', buildReportAndHashes);
  $('downloadReportBtn').addEventListener('click', () => {
    if (state.report) download(`veilproof-report-${state.report.reportId}.json`, state.report);
  });
  $('downloadDisclosureBtn').addEventListener('click', () => {
    if (state.disclosurePackage) {
      download(`veilproof-disclosure-${state.disclosurePackage.reportId}.json`, state.disclosurePackage);
    }
  });
  $('encryptDisclosureBtn').addEventListener('click', encryptDisclosureForVerifier);
  $('downloadEncryptedBtn').addEventListener('click', () => {
    if (state.encryptedDisclosurePackage) {
      download(`veilproof-disclosure-encrypted-${state.report.reportId}.json`, state.encryptedDisclosurePackage);
    }
  });
  $('publishConfirm').addEventListener('change', () => {
    refreshPublishBtn();
  });
  $('publishBtn').addEventListener('click', publish);
  // Restore a previous wallet session (same pattern as Genesis).
  try {
    const nw = fastnear();
    const restored = await nw.restore({ network: NETWORK });
    const id = restored && typeof restored.accountId === 'string' ? restored.accountId : null;
    if (id && !state.accountId) {
      state.accountId = id;
      updateWalletUI();
      saveState();
    }
  } catch (err) {
    console.warn('FastNear restore:', err);
  }
});
