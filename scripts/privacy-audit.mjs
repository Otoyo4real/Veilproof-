// VeilProof privacy audit — the attacker script.
//
//   npm run audit
//
// The attacker receives ONLY public data: the public reports, the
// registry's public views (get_claim / get_owner_claims), and public
// API responses (the committed demo report). It never sees an address,
// a snapshot, or a disclosure package — anything it recovers came
// from public data alone.
//
// Three attacks, over 50 simulated provers (2 reports each, 100 total):
//   (a) address recovery — hash a dictionary of plausible names and
//       compare with the prover commitments.
//   (b) linking — group reports by identical prover commitment, and
//       separately by the registry's public owner field, and measure
//       pairwise precision against the chance baseline.
//   (c) balance / score estimation — read the best estimate of the
//       exact aggregate balance and exact score from the public
//       report, and measure the error against the true values.
//
// The audit is a MEASUREMENT, not a gate: it always exits 0 and
// prints its verdict ("LEAKS FOUND" or "CLEAN"). The tests in
// test/privacy-audit.test.mjs are the gate — they assert 0 address
// recoveries and linking no better than chance, and they fail while
// the leaks below exist. That failure IS the before/after evidence:
// fix the leak (P2 salts, P3 predicates), re-run, watch them pass.
//
// Deterministic: a seeded RNG, so the same run gives the same table.
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import { evaluateClaims } from '../src/claims-engine.js';
import { computeScore } from '../src/score.js';
import { computeDataHash } from '../src/onchain.js';
import { buildReport } from '../src/report.js';

const NEAR = 10n ** 24n;
const NOW_NS = 1793961600000000000n;
const DAY_NS = 86400n * 1_000_000_000n;
const EXPIRES_AT = (NOW_NS + 30n * DAY_NS).toString();
const POLICY_VERSION = 'veilproof-policy-v1';
const POLICY = {
  balanceAtLeastYocto: (1n * NEAR).toString(),
  aggregateBalanceAtLeastYocto: (1n * NEAR).toString(),
  sustainedBalanceAtLeastYocto: (1n * NEAR).toString(),
  timeWeightedBalanceAtLeastYocto: (1n * NEAR).toString(),
  minTxCount: 2,
  txWindowDays: 30,
  minVolumeYocto: (1n * NEAR).toString(),
  volumeWindowDays: 30,
  noFailedWindowDays: 30,
};
const SCORE_OPTS = { txWindowDays: 30, volumeWindowDays: 30, noFailedWindowDays: 30 };

// Names an attacker would plausibly try: the publicly known demo
// wallets plus common agent/treasury names. Five of the 50 simulated
// provers use names from this list (real agents pick readable names);
// the other 45 use random subaccount names.
const DICTIONARY = [
  'veilproof-demo.testnet',
  'veilproof.testnet',
  'demo2.veilproof.testnet',
  'alice.testnet',
  'bob.testnet',
  'agent.testnet',
  'treasury.testnet',
  'demo.testnet',
  'test.testnet',
  'user.testnet',
  'wallet.testnet',
  'prover.testnet',
  'main.testnet',
  'vault.testnet',
  'fund.testnet',
  'pool.testnet',
  'agent1.testnet',
  'agent-1.testnet',
  'treasury1.testnet',
  'otoyo.testnet',
  'bot.testnet',
  'trader.testnet',
  'market.testnet',
  'escrow.testnet',
  'reserve.testnet',
];

function sha256Hex(s) {
  return createHash('sha256').update(s, 'utf8').digest('hex');
}

// Deterministic RNG (mulberry32) so the audit is reproducible.
function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function randomHex(rng, chars) {
  const alphabet = '0123456789abcdef';
  let out = '';
  for (let i = 0; i < chars; i++) out += alphabet[Math.floor(rng() * 16)];
  return out;
}

// One realistic single-wallet snapshot for a prover.
function makeSnapshot(rng, address, balanceNear) {
  const balance = BigInt(balanceNear) * NEAR;
  const txCount = 2 + Math.floor(rng() * 13);
  const txs = [];
  for (let i = 0; i < txCount; i++) {
    const counterparty = `counterparty-${randomHex(rng, 6)}.testnet`;
    const amount = BigInt(1 + Math.floor(rng() * 40)) * (NEAR / 10n);
    const daysAgo = 1 + Math.floor(rng() * 28);
    txs.push({
      hash: randomHex(rng, 43),
      senderId: rng() < 0.5 ? address : counterparty,
      receiverId: rng() < 0.5 ? counterparty : address,
      amountYocto: amount.toString(),
      status: 'Success',
      blockHeight: 90 + i,
      blockTimestampNs: (NOW_NS - BigInt(daysAgo) * DAY_NS).toString(),
    });
  }
  // Balance samples: 4 past heights, lowest sample is the sustained balance.
  const samples = [0, 1, 2, 3].map((i) => ({
    blockHeight: 90 + i,
    amount: (balance - BigInt(Math.floor(rng() * 3)) * (NEAR / 10n)).toString(),
  }));
  const snap = {
    account: {
      accountId: address,
      amount: balance.toString(),
      locked: '0',
      storage_usage: 182,
      blockHeight: 100,
    },
    txs,
    blockHeight: 100,
    balanceSamples: samples,
  };
  snap.dataHash = computeDataHash(snap.account.accountId, snap.account.amount, snap.account.locked, snap.txs);
  return snap;
}

function makeReport(rng, address, balanceNear) {
  const snap = makeSnapshot(rng, address, balanceNear);
  const { claims } = evaluateClaims(snap, POLICY, NOW_NS);
  const score = computeScore(snap, SCORE_OPTS, NOW_NS.toString(), 'score-v2');
  const report = buildReport({
    proverAddressHash: sha256Hex(address),
    claims,
    policyVersion: POLICY_VERSION,
    aiSummary: null,
    evidenceRefs: { dataHash: snap.dataHash, attestationRef: null },
    expiresAt: EXPIRES_AT,
    score,
  });
  return { address, snapshot: snap, report, score, aggregateBalance: BigInt(snap.account.amount) };
}

// Simulated registry: the attacker's only view is get_claim (which
// returns the record INCLUDING the owner account) and get_owner_claims
// (all claim ids for an owner, in publication order) — exactly the
// real contract's public views.
function simulateRegistry(published) {
  const claims = new Map();
  const ownerClaims = new Map();
  for (const p of published) {
    claims.set(p.report.reportId, {
      claim_id: p.report.reportId,
      owner: p.address,
      report_hash: 'hash',
      evidence_hash: 'hash',
      policy_hash: 'hash',
      expires_at: p.report.expiresAt,
      valid: true,
    });
    if (!ownerClaims.has(p.address)) ownerClaims.set(p.address, []);
    ownerClaims.get(p.address).push(p.report.reportId);
  }
  return { claims, ownerClaims };
}

// Attack (a): dictionary recovery of prover commitments.
function attackAddressRecovery(reports, dictionary) {
  const byHash = new Map(dictionary.map((name) => [sha256Hex(name), name]));
  const recovered = new Set();
  for (const r of reports) {
    const hit = byHash.get(r.report.prover);
    if (hit) recovered.add(r.address);
    for (const linked of r.report.linkedProvers || []) {
      const lhit = byHash.get(linked);
      if (lhit) recovered.add(lhit);
    }
  }
  return recovered;
}

// Attack (b): linking. Group items by a key; pairwise precision is
// the fraction of predicted "same prover" pairs that truly are, and
// the chance baseline is the fraction of ALL pairs that are same-prover.
function linkingStats(groups, truth) {
  let predicted = 0;
  let truePredicted = 0;
  for (const group of groups.values()) {
    for (let i = 0; i < group.length; i++) {
      for (let j = i + 1; j < group.length; j++) {
        predicted++;
        if (truth(group[i]) === truth(group[j])) truePredicted++;
      }
    }
  }
  return { predicted, truePredicted, precision: predicted === 0 ? null : truePredicted / predicted };
}

// Attack (c): best estimate of the exact values from the public report.
// A claim value, when present, IS the exact measured amount; a missing
// value leaves only the threshold (a predicate). A score value, when
// present, IS the exact score; a missing value leaves only the band.
const BAND_MIDPOINT = { thin: 149.5, building: 449.5, solid: 699.5, strong: 900 };
function estimateBalance(report) {
  const claim = (report.claims || []).find((c) => c.id === 'aggregate_balance_at_least');
  if (!claim) return null;
  if (claim.value !== undefined) return BigInt(claim.value);
  return BigInt(claim.threshold);
}
function estimateScore(report) {
  if (report.score?.value !== undefined && report.score.value !== null) return report.score.value;
  if (report.score?.band) return BAND_MIDPOINT[report.score.band];
  return null;
}

export function runAudit() {
  const rng = mulberry32(20261106);
  const provers = [];
  for (let i = 0; i < 50; i++) {
    const dictionaryNamed = i < 5;
    const address = dictionaryNamed
      ? DICTIONARY[i]
      : `${randomHex(rng, 8)}.testnet`;
    provers.push({ address, dictionaryNamed, reports: [] });
  }
  const published = [];
  for (const prover of provers) {
    // Two reports per prover, different balances/txs, same address.
    for (let k = 0; k < 2; k++) {
      const balanceNear = 2 + Math.floor(rng() * 48);
      const made = makeReport(rng, prover.address, balanceNear);
      prover.reports.push(made);
      published.push(made);
    }
  }
  const registry = simulateRegistry(published);
  const reports = published.map((p) => p.report);
  const truthByReport = new Map(published.map((p) => [p.report.reportId, p.address]));

  // (a) Address recovery.
  const recovered = attackAddressRecovery(published, DICTIONARY);
  const randomProvers = provers.filter((p) => !p.dictionaryNamed);
  const dictProvers = provers.filter((p) => p.dictionaryNamed);
  const randomRecovered = randomProvers.filter((p) => recovered.has(p.address)).length;
  const dictRecovered = dictProvers.filter((p) => recovered.has(p.address)).length;

  // (b) Linking via report commitments.
  const byCommitment = new Map();
  for (const p of published) {
    if (!byCommitment.has(p.report.prover)) byCommitment.set(p.report.prover, []);
    byCommitment.get(p.report.prover).push(p.report.reportId);
  }
  const commitLink = linkingStats(byCommitment, (id) => truthByReport.get(id));
  // Linking via the registry's public owner field.
  const byOwner = new Map();
  for (const [owner, ids] of registry.ownerClaims) byOwner.set(owner, ids);
  const ownerLink = linkingStats(byOwner, (id) => truthByReport.get(id));
  // Chance baseline: same-prover pairs / all pairs.
  const totalPairs = (reports.length * (reports.length - 1)) / 2;
  const truePairs = provers.length; // 2 reports each -> 1 pair per prover
  const chance = truePairs / totalPairs;

  // (c) Balance / score estimation error (mean absolute % error).
  let balanceErr = 0;
  let balanceN = 0;
  let scoreErr = 0;
  let scoreN = 0;
  for (const p of published) {
    const estBal = estimateBalance(p.report);
    if (estBal !== null) {
      const trueBal = p.aggregateBalance;
      balanceErr += Number((estBal > trueBal ? estBal - trueBal : trueBal - estBal) * 10000n / trueBal) / 100;
      balanceN++;
    }
    const estScore = estimateScore(p.report);
    if (estScore !== null) {
      scoreErr += (Math.abs(estScore - p.score.value) / p.score.value) * 100;
      scoreN++;
    }
  }

  // Live demo claim (the real published report, public data only).
  const live = { present: false };
  try {
    const demo = JSON.parse(fs.readFileSync(new URL('../public/demo-report.json', import.meta.url), 'utf8'));
    const dictHit = DICTIONARY.some((name) => sha256Hex(name) === demo.prover)
      || (demo.linkedProvers || []).some((h) => DICTIONARY.some((name) => sha256Hex(name) === h));
    const liveBal = estimateBalance(demo);
    const liveScore = estimateScore(demo);
    live.present = true;
    live.reportId = demo.reportId;
    live.addressRecoveredByDictionary = dictHit;
    live.balanceEstimateExact = liveBal !== null && demo.claims.some((c) => c.id === 'aggregate_balance_at_least' && c.value !== undefined);
    live.scoreEstimateExact = demo.score?.value !== undefined && demo.score.value !== null;
    live.scoreValue = demo.score?.value ?? null;
    live.balanceEstimate = liveBal !== null ? liveBal.toString() : null;
    void liveScore;
  } catch {
    live.present = false;
  }

  const leaks = [];
  if (recovered.size > 0) leaks.push('address recovery');
  if (commitLink.precision !== null && commitLink.precision > chance) leaks.push('linking via commitments');
  if (balanceN > 0 && balanceErr / balanceN < 1) leaks.push('exact balance from public report');
  if (scoreN > 0 && scoreErr / scoreN < 1) leaks.push('exact score from public report');

  return {
    provers: 50,
    reports: reports.length,
    addressRecovery: {
      recovered: recovered.size,
      of: 50,
      randomRecovered,
      randomOf: randomProvers.length,
      dictionaryRecovered: dictRecovered,
      dictionaryOf: dictProvers.length,
    },
    linkingByCommitment: {
      predictedPairs: commitLink.predicted,
      truePairs: commitLink.truePredicted,
      precision: commitLink.precision,
      chance,
      betterThanChance: commitLink.precision !== null && commitLink.precision > chance,
    },
    linkingByOwner: {
      predictedPairs: ownerLink.predicted,
      truePairs: ownerLink.truePredicted,
      precision: ownerLink.precision,
      chance,
      betterThanChance: ownerLink.precision !== null && ownerLink.precision > chance,
      note: 'The registry owner field is public by design (revocation needs an owner). Salts do not fix this; see docs/privacy-audit.md.',
    },
    balanceEstimation: { meanAbsPctError: balanceN ? balanceErr / balanceN : null, n: balanceN },
    scoreEstimation: { meanAbsPctError: scoreN ? scoreErr / scoreN : null, n: scoreN },
    liveDemo: live,
    leaks,
    verdict: leaks.length === 0 ? 'CLEAN' : 'LEAKS FOUND',
  };
}

function pct(x) {
  return x === null || x === undefined ? 'n/a' : `${(x * 100).toFixed(1)}%`;
}
function errPct(x) {
  return x === null || x === undefined ? 'n/a' : `${x.toFixed(2)}%`;
}

const isMain = process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href;
if (isMain) {
  const r = runAudit();
  console.log('VeilProof privacy audit — attacker sees ONLY public data');
  console.log(`Simulated provers: ${r.provers}, reports: ${r.reports} (2 per prover)`);
  console.log('');
  console.log('Attack                                Result              Chance/baseline   Verdict');
  console.log('------------------------------------  ------------------  ----------------  ----------------');
  const a = r.addressRecovery;
  console.log(`(a) Address recovery (dictionary)     ${a.recovered}/${a.of} recovered  ${a.randomRecovered}/${a.randomOf} random, ${a.dictionaryRecovered}/${a.dictionaryOf} named  ${a.recovered === 0 ? 'PASS' : 'LEAK'}`);
  const l = r.linkingByCommitment;
  console.log(`(b) Linking via prover commitment     precision ${pct(l.precision)}  chance ${pct(l.chance)}       ${l.betterThanChance ? 'LEAK' : 'PASS'}`);
  const o = r.linkingByOwner;
  console.log(`(b) Linking via registry owner field  precision ${pct(o.precision)}  chance ${pct(o.chance)}       ${o.betterThanChance ? 'LEAK (documented limit)' : 'PASS'}`);
  console.log(`(c) Balance estimate error (mean)     ${errPct(r.balanceEstimation.meanAbsPctError)}             exact = 0%         ${r.balanceEstimation.meanAbsPctError < 1 ? 'LEAK' : 'PASS'}`);
  console.log(`(c) Score estimate error (mean)       ${errPct(r.scoreEstimation.meanAbsPctError)}             exact = 0%         ${r.scoreEstimation.meanAbsPctError < 1 ? 'LEAK' : 'PASS'}`);
  if (r.liveDemo.present) {
    const d = r.liveDemo;
    console.log(`Live demo claim ${d.reportId}: dictionary recovery ${d.addressRecoveredByDictionary ? 'YES' : 'no'}, exact balance visible ${d.balanceEstimateExact ? 'YES' : 'no'}, exact score visible ${d.scoreEstimateExact ? 'YES' : 'no'} (score ${d.scoreValue})`);
  }
  console.log('');
  console.log(`Verdict: ${r.verdict}${r.leaks.length ? ` — ${r.leaks.join(', ')}` : ''}`);
}
