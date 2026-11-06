// VeilProof portable credit score — version 1 (score-v1).
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
// Rules (score-v1), all thresholds in NEAR, all amounts compared as
// yocto BigInts. Total 1000 points. A feature the prover did not
// measure scores 0 and is marked measured:false — the score never
// hides what it did not see.
//
// - sustained_balance (max 300): the LOWEST sampled balance across
//   the sampled window. <0.1 NEAR: 0; 0.1–0.49: 50; 0.5–0.99: 120;
//   1–4.99: 200; 5–9.99: 260; >=10: 300. Measured only when every
//   wallet carries balanceSamples.
// - time_weighted_balance (max 200): the MEAN sampled balance.
//   <0.1: 0; 0.1–0.49: 40; 0.5–0.99: 80; 1–4.99: 130; 5–9.99: 170;
//   >=10: 200. Measured only when samples exist.
// - activity (max 200): Success txs in the tx window. 0: 0; 1–2: 40;
//   3–9: 90; 10–29: 140; >=30: 170; +30 when the Success txs span at
//   least 3 distinct ISO calendar weeks inside the window (spread
//   beats a burst: one afternoon of wash txs cannot max this out).
//   Measured only when txWindowDays is supplied.
// - volume (max 150): summed volume in the volume window, each tx
//   counted once across all wallets. <0.1: 0; 0.1–0.49: 30; 0.5–0.99:
//   60; 1–4.99: 100; 5–9.99: 130; >=10: 150. Measured only when
//   volumeWindowDays is supplied.
// - no_failed (max 100): 100 when zero failed txs in the no-failed
//   window, 0 otherwise. Measured only when noFailedWindowDays is
//   supplied.
// - staked (max 50): 50 when the summed staked (locked) balance
//   across wallets is > 0, else 0. Always measured.
//
// Bands: 0–299 thin, 300–599 building, 600–799 solid, 800–1000 strong.
// A band is a label, not a lending decision: the AI underwriter
// (ai-analysis.js) gives the advisory verdict, and the deterministic
// score is the fact it must not contradict.
//
// The score is calibrated for testnet-scale demo treasuries (a ~10
// NEAR wallet scores in the solid band when its history is clean).
// Mainnet-scale treasuries would use a recalibrated score-v2 with
// larger bands; the version field exists so v1 and v2 scores are
// never confused.

import {
  normalizeBundle,
  unionTxs,
  aggregateStaked,
  sampleSums,
} from './claims-engine.js';

export const SCORE_VERSION = 'score-v1';
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

// Compute the score-v1 score for a snapshot or bundle.
// opts windows (all optional, in days): txWindowDays,
// volumeWindowDays, noFailedWindowDays. nowNs is required when any
// window is supplied. Returns
// { version, value, band, components: [{ id, label, points, max, measured }] }.
export function computeScore(snapshotOrBundle, opts = {}, nowNs) {
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
    const minNear = min;
    const avgNear = avg;
    const sustainedPoints = tierPoints(minNear, [[0.1, 50], [0.5, 120], [1, 200], [5, 260], [10, 300]]);
    const weightedPoints = tierPoints(avgNear, [[0.1, 40], [0.5, 80], [1, 130], [5, 170], [10, 200]]);
    push('sustained_balance', 'Lowest sampled balance held', sustainedPoints, 300, true);
    push('time_weighted_balance', 'Average sampled balance', weightedPoints, 200, true);
  } else {
    push('sustained_balance', 'Lowest sampled balance held', 0, 300, false);
    push('time_weighted_balance', 'Average sampled balance', 0, 200, false);
  }

  const txs = unionTxs(wallets);
  const now = nowNs === undefined ? null : BigInt(nowNs);

  // Activity: Success tx count + week spread in the tx window.
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
    const count = inWindow.length;
    const weeks = distinctWeeks(inWindow.map((tx) => tx.blockTimestampNs));
    let points = count >= 30 ? 170 : count >= 10 ? 140 : count >= 3 ? 90 : count >= 1 ? 40 : 0;
    if (weeks >= 3 && points > 0) points = Math.min(200, points + 30);
    push('activity', 'Successful transactions and week spread', points, 200, true);
  } else {
    push('activity', 'Successful transactions and week spread', 0, 200, false);
  }

  // Volume: summed once per tx across all wallets.
  if (windows.volumeWindowDays !== undefined && now !== null) {
    const days = windows.volumeWindowDays;
    if (typeof days !== 'number' || !Number.isInteger(days) || days < 0) {
      throw new Error('score: volumeWindowDays must be a non-negative integer number of days');
    }
    const start = now - BigInt(days) * NS_PER_DAY;
    const ids = new Set(wallets.map((w) => w.account.accountId));
    let sum = 0n;
    for (const tx of txs) {
      const ts = BigInt(tx.blockTimestampNs);
      if (ts < start || ts > now || tx.status !== 'Success') continue;
      if (!ids.has(tx.senderId) && !ids.has(tx.receiverId)) continue;
      sum += BigInt(tx.amountYocto);
    }
    const points = tierPoints(sum, [[0.1, 30], [0.5, 60], [1, 100], [5, 130], [10, 150]]);
    push('volume', 'Volume in window', points, 150, true);
  } else {
    push('volume', 'Volume in window', 0, 150, false);
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

  const value = components.reduce((sum, c) => sum + c.points, 0);
  return { version: SCORE_VERSION, value, band: bandFor(value), components };
}
