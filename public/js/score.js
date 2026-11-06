// VeilProof portable credit score — versions 1 and 2.
//
// A deterministic, recomputable reputation score for an agent (or any
// prover) built ONLY from onchain facts: sampled balances, transaction
// counts and volumes, failed-tx history, and staking. No AI, no
// offchain data, no identity. Anyone holding the disclosure package
// can recompute the exact same score from the same snapshots with the
// same windows — that is what makes it reusable across apps: the score
// is a portable credential, and the published rules below are the
// shared recipe every app runs. The score is pinned in the report and
// the verifier re-runs it (see verify-report.js); a tampered score
// fails verification.
//
// Rules (score-v2, current), all thresholds in NEAR, all amounts
// compared as yocto BigInts. Total 1000 points. A feature the prover
// did not measure scores 0 and is marked measured:false — the score
// never hides what it did not see.
//
// - sustained_balance (max 350): the LOWEST sampled balance across
//   the sampled window. <0.1 NEAR: 0; 0.1–0.49: 60; 0.5–0.99: 140;
//   1–4.99: 230; 5–9.99: 300; >=10: 350. Measured only when every
//   wallet carries balanceSamples. Hardest to fake: it costs real
//   capital held over time, so it carries the largest weight.
// - time_weighted_balance (max 150): the MEAN sampled balance.
//   <0.1: 0; 0.1–0.49: 30; 0.5–0.99: 60; 1–4.99: 100; 5–9.99: 130;
//   >=10: 150. Measured only when samples exist.
// - activity (max 150): EXTERNAL Success txs in the tx window — a tx
//   counts only when at least one endpoint is outside the bundle.
//   0: 0; 1–2: 30; 3–9: 70; 10–29: 105; >=30: 130; +20 when the
//   counted txs span at least 3 distinct ISO calendar weeks inside
//   the window, capped at 150. Measured only when txWindowDays is
//   supplied.
// - volume (max 100): summed EXTERNAL volume in the volume window,
//   each tx counted once across all wallets. <0.1: 0; 0.1–0.49: 20;
//   0.5–0.99: 40; 1–4.99: 70; 5–9.99: 90; >=10: 100. Measured only
//   when volumeWindowDays is supplied.
// - counterparty_diversity (max 100, NEW in v2): distinct OUTSIDE
//   counterparties among the Success txs in the tx window — any
//   sender or receiver that is not one of the bundle's own wallets.
//   0: 0; 1: 30; 2–3: 60; 4–9: 85; >=10: 100. Measured only when
//   txWindowDays is supplied.
// - no_failed (max 100): 100 when zero failed txs in the no-failed
//   window, 0 otherwise. Measured only when noFailedWindowDays is
//   supplied.
// - staked (max 50): 50 when the summed staked (locked) balance
//   across wallets is > 0, else 0. Always measured.
//
// An external tx is one where at least one endpoint is in the bundle
// and at least one endpoint is outside it. A transfer between two of
// the prover's own wallets is internal and earns nothing in v2's
// activity, volume or diversity — that is the whole point: a prover
// washing 12 NEAR between two of their own wallets for an afternoon
// scores 600 under v2 (sustained 350 + time-weighted 150 + no_failed
// 100), down from 920 under v1, while an honest treasury barely
// moves (the demo: 790 v1 -> 770 v2).
//
// Manipulation detection (score-v2, see src/manipulation.js): the
// score never sees identity, so it cannot tell a sock-puppet from a
// stranger — but it can see pattern. computeScore runs the detectors
// over the tx window and returns their findings alongside the points:
// - riskFlags: [{ type, detail, severity }] — circular flows and
//   chains, shared funders, concentrated counterparties, repeated
//   transfers, internal transfers. Advisory only: flags never change
//   the points. Diversity earned from a flagged counterparty is
//   FLAGGED, not discounted — discounting would change published
//   scores, and a future score-v3 may discount; v2 only flags.
// - counterpartyLabels: [{ account, label }] — 'own' for bundle
//   wallets, 'suspicious' for an outside account that appears in a
//   medium/high flag, 'unknown' for every other outside account.
//   UNKNOWN means "no identity or ownership evidence exists, so
//   independence is NOT assumed" — diversity counts distinct
//   accounts, not proven-independent counterparties.
// - disclaimer: the score measures observable onchain activity only;
//   it is not a guarantee of repayment, identity, beneficial
//   ownership, or creditworthiness.
// Detection runs only when txWindowDays is supplied (it needs the
// window); otherwise riskFlags and counterpartyLabels are empty.
//
// NOTE on labels: the component labels below are part of published
// reports' onchain-pinned hashes, so they are not renamed lightly.
// 'Lowest sampled balance held' already says "sampled", never
// "continuously held" — the honest "lowest OBSERVED sampled balance"
// wording lives in the sampling record (src/sampling.js) and the
// docs, and no claim or label here describes a sampled balance as
// maintained between samples.
//
// score-v1 (kept for old reports — the verifier recomputes a report
// under its own version, so v1 reports still verify exactly): the
// same six components, but activity is max 200 (0: 0; 1–2: 40; 3–9:
// 90; 10–29: 140; >=30: 170; +30 spread bonus, capped at 200) and
// counts every tx, volume is max 150 and counts every tx, there is
// no counterparty_diversity component, sustained is max 300
// (50/120/200/260/300) and time-weighted is max 200
// (40/80/130/170/200).
//
// Bands (both versions): 0–299 thin, 300–599 building, 600–799
// solid, 800–1000 strong. A band is a label, not a lending decision:
// the AI underwriter (ai-analysis.js) gives the advisory verdict,
// and the deterministic score is the fact it must not contradict.
//
// The score is calibrated for testnet-scale demo treasuries (a ~10
// NEAR wallet scores in the solid band when its history is clean).
// Mainnet-scale treasuries would use a recalibrated score-v3 with
// larger bands; the version field exists so versions are never
// confused.

import {
  normalizeBundle,
  unionTxs,
  aggregateStaked,
  sampleSums,
} from './claims-engine.js';
import {
  SCORE_DISCLAIMER,
  detectRiskFlags,
  labelCounterparties,
  counterpartySummary,
} from './manipulation.js';

export const SCORE_VERSION = 'score-v2';
export const SCORE_MAX = 1000;

const YOCTO_PER_NEAR = 10n ** 24n;
const NS_PER_DAY = 86400n * 1_000_000_000n;

// Points for the highest tier the yocto value reaches. Tiers are
// [threshold in NEAR (whole or tenth), points], ascending.
function tierPoints(valueYocto, tiers) {
  let points = 0;
  for (const [nearThreshold, tierPts] of tiers) {
    const thresholdYocto = (BigInt(Math.round(nearThreshold * 10)) * YOCTO_PER_NEAR) / 10n;
    if (valueYocto >= thresholdYocto) points = tierPts;
  }
  return points;
}

function bandFor(value) {
  if (value >= 800) return 'strong';
  if (value >= 600) return 'solid';
  if (value >= 300) return 'building';
  return 'thin';
}

// Distinct ISO calendar weeks (YYYY-Www) among the given nanosecond
// timestamps. Weeks start on Monday (ISO 8601).
function distinctWeeks(timestampsNs) {
  const weeks = new Set();
  for (const ts of timestampsNs) {
    const ms = Number(BigInt(ts) / 1_000_000n);
    const d = new Date(ms);
    const day = (d.getUTCDay() + 6) % 7; // Monday = 0
    const monday = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() - day));
    const yearStart = Date.UTC(monday.getUTCFullYear(), 0, 1);
    const week = Math.floor((monday.getTime() - yearStart) / (7 * 86400 * 1000)) + 1;
    weeks.add(`${monday.getUTCFullYear()}-W${String(week).padStart(2, '0')}`);
  }
  return weeks.size;
}

// Version rules. v1 counts every tx and every unit of volume the
// same, including transfers between the prover's own wallets — a
// prover can wash 12 NEAR between two of their own wallets for an
// afternoon and score 920/1000 (strong) with zero outside
// counterparties. v2 stops rewarding self-dealing: activity and
// volume count EXTERNAL txs only (at least one endpoint outside the
// bundle), sustained balance — the one component that costs real
// capital held over time — grows to 350, and a counterparty
// diversity component (100) rewards real economic counterparties.
// An honest treasury barely moves (the demo: 790 v1 -> 770 v2); the
// wash attack above collapses to 600. Full rules: docs/score-v2.md
// (v2) and docs/score-v1.md (v1).
const SCORE_RULES = {
  'score-v1': {
    sustained: { max: 300, tiers: [[0.1, 50], [0.5, 120], [1, 200], [5, 260], [10, 300]] },
    timeWeighted: { max: 200, tiers: [[0.1, 40], [0.5, 80], [1, 130], [5, 170], [10, 200]] },
    activity: { max: 200, tiers: [[1, 40], [3, 90], [10, 140], [30, 170]], spreadBonus: 30, externalOnly: false },
    volume: { max: 150, tiers: [[0.1, 30], [0.5, 60], [1, 100], [5, 130], [10, 150]], externalOnly: false },
    diversity: null,
  },
  'score-v2': {
    sustained: { max: 350, tiers: [[0.1, 60], [0.5, 140], [1, 230], [5, 300], [10, 350]] },
    timeWeighted: { max: 150, tiers: [[0.1, 30], [0.5, 60], [1, 100], [5, 130], [10, 150]] },
    activity: { max: 150, tiers: [[1, 30], [3, 70], [10, 105], [30, 130]], spreadBonus: 20, externalOnly: true },
    volume: { max: 100, tiers: [[0.1, 20], [0.5, 40], [1, 70], [5, 90], [10, 100]], externalOnly: true },
    diversity: { max: 100, tiers: [[1, 30], [2, 60], [4, 85], [10, 100]] },
  },
};

// Points for the highest tier the count reaches. Tiers are
// [threshold (count), points], ascending.
function countTierPoints(count, tiers) {
  let points = 0;
  for (const [threshold, tierPts] of tiers) {
    if (count >= threshold) points = tierPts;
  }
  return points;
}

// Compute the score for a snapshot or bundle.
// opts windows (all optional, in days): txWindowDays,
// volumeWindowDays, noFailedWindowDays. nowNs is required when any
// window is supplied. version is 'score-v2' by default; pass
// 'score-v1' to recompute an old report under its own rules (the
// verifier does this from report.score.version). Returns
// { version, value, band, components: [{ id, label, points, max,
// measured }], riskFlags, counterpartyLabels, counterpartySummary,
// disclaimer }.
export function computeScore(snapshotOrBundle, opts = {}, nowNs, version = SCORE_VERSION) {
  const rules = SCORE_RULES[version];
  if (!rules) {
    throw new Error(`score: unknown version ${version}`);
  }
  const wallets = normalizeBundle(snapshotOrBundle);
  const windows = opts || {};
  const components = [];

  const push = (id, label, points, max, measured) => {
    components.push({ id, label, points, max, measured });
  };

  // Sustained + time-weighted balance (need aligned samples).
  let sampled = null;
  try {
    sampled = sampleSums(wallets);
  } catch {
    sampled = null;
  }
  if (sampled) {
    const min = sampled.reduce((m, s) => (s.amount < m ? s.amount : m), sampled[0].amount);
    const total = sampled.reduce((acc, s) => acc + s.amount, 0n);
    const avg = total / BigInt(sampled.length);
    push('sustained_balance', 'Lowest sampled balance held', tierPoints(min, rules.sustained.tiers), rules.sustained.max, true);
    push('time_weighted_balance', 'Average sampled balance', tierPoints(avg, rules.timeWeighted.tiers), rules.timeWeighted.max, true);
  } else {
    push('sustained_balance', 'Lowest sampled balance held', 0, rules.sustained.max, false);
    push('time_weighted_balance', 'Average sampled balance', 0, rules.timeWeighted.max, false);
  }

  const txs = unionTxs(wallets);
  const now = nowNs === undefined ? null : BigInt(nowNs);
  const own = new Set(wallets.map((w) => w.account.accountId));
  // An external tx has at least one endpoint in the bundle and at
  // least one endpoint outside it. A transfer between two of the
  // prover's own wallets is internal and earns nothing in v2's
  // activity, volume or diversity.
  const isExternal = (tx) =>
    (own.has(tx.senderId) || own.has(tx.receiverId)) && (!own.has(tx.senderId) || !own.has(tx.receiverId));

  // Activity + counterparty diversity share the tx window.
  if (windows.txWindowDays !== undefined && now !== null) {
    const days = windows.txWindowDays;
    if (typeof days !== 'number' || !Number.isInteger(days) || days < 0) {
      throw new Error('score: txWindowDays must be a non-negative integer number of days');
    }
    const start = now - BigInt(days) * NS_PER_DAY;
    const inWindow = txs.filter((tx) => {
      const ts = BigInt(tx.blockTimestampNs);
      return ts >= start && ts <= now && tx.status === 'Success';
    });
    const counted = rules.activity.externalOnly ? inWindow.filter(isExternal) : inWindow;
    const count = counted.length;
    const weeks = distinctWeeks(counted.map((tx) => tx.blockTimestampNs));
    let points = countTierPoints(count, rules.activity.tiers);
    if (weeks >= 3 && points > 0) points = Math.min(rules.activity.max, points + rules.activity.spreadBonus);
    push('activity', 'Successful transactions and week spread', points, rules.activity.max, true);
    if (rules.diversity) {
      const counterparties = new Set();
      for (const tx of counted) {
        if (tx.senderId && !own.has(tx.senderId)) counterparties.add(tx.senderId);
        if (tx.receiverId && !own.has(tx.receiverId)) counterparties.add(tx.receiverId);
      }
      push('counterparty_diversity', 'Distinct outside counterparties', countTierPoints(counterparties.size, rules.diversity.tiers), rules.diversity.max, true);
    }
  } else {
    push('activity', 'Successful transactions and week spread', 0, rules.activity.max, false);
    if (rules.diversity) push('counterparty_diversity', 'Distinct outside counterparties', 0, rules.diversity.max, false);
  }

  // Volume: summed once per tx across all wallets.
  if (windows.volumeWindowDays !== undefined && now !== null) {
    const days = windows.volumeWindowDays;
    if (typeof days !== 'number' || !Number.isInteger(days) || days < 0) {
      throw new Error('score: volumeWindowDays must be a non-negative integer number of days');
    }
    const start = now - BigInt(days) * NS_PER_DAY;
    let sum = 0n;
    for (const tx of txs) {
      const ts = BigInt(tx.blockTimestampNs);
      if (ts < start || ts > now || tx.status !== 'Success') continue;
      if (!own.has(tx.senderId) && !own.has(tx.receiverId)) continue;
      if (rules.volume.externalOnly && !isExternal(tx)) continue;
      sum += BigInt(tx.amountYocto);
    }
    push('volume', 'Volume in window', tierPoints(sum, rules.volume.tiers), rules.volume.max, true);
  } else {
    push('volume', 'Volume in window', 0, rules.volume.max, false);
  }

  // No failed txs in window.
  if (windows.noFailedWindowDays !== undefined && now !== null) {
    const days = windows.noFailedWindowDays;
    if (typeof days !== 'number' || !Number.isInteger(days) || days < 0) {
      throw new Error('score: noFailedWindowDays must be a non-negative integer number of days');
    }
    const start = now - BigInt(days) * NS_PER_DAY;
    const failed = txs.filter((tx) => {
      const ts = BigInt(tx.blockTimestampNs);
      return ts >= start && ts <= now && tx.status === 'Failure';
    }).length;
    push('no_failed', 'No failed transactions in window', failed === 0 ? 100 : 0, 100, true);
  } else {
    push('no_failed', 'No failed transactions in window', 0, 100, false);
  }

  // Staked: always measurable from the accounts themselves.
  push('staked', 'Staked balance held', aggregateStaked(wallets) > 0n ? 50 : 0, 50, true);

  // Manipulation detection over the tx window (advisory: flags never
  // change the points). Unassessed when no tx window was supplied.
  const assessed = windows.txWindowDays !== undefined && now !== null;
  const riskFlags = assessed
    ? detectRiskFlags(snapshotOrBundle, { txWindowDays: windows.txWindowDays, nowNs }).flags
    : [];
  const labels = assessed
    ? labelCounterparties(snapshotOrBundle, { txWindowDays: windows.txWindowDays, nowNs })
    : [];

  const value = components.reduce((sum, c) => sum + c.points, 0);
  return {
    version,
    value,
    band: bandFor(value),
    components,
    riskFlags,
    counterpartyLabels: labels,
    counterpartySummary: counterpartySummary(labels),
    disclaimer: SCORE_DISCLAIMER,
  };
}
