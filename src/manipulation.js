// VeilProof manipulation detection — PURE deterministic functions.
//
// The score measures observable onchain activity. It cannot see
// identity: two accounts that look independent may be one person's
// sock-puppets, and no onchain check can prove otherwise. What it
// CAN see is pattern: money that leaves and comes back, the same
// transfer repeated, all activity funnelled through one account,
// several wallets sharing one funder. This module detects exactly
// those patterns — and nothing it cannot observe — from the disclosed
// txs in the score's tx window.
//
// Rules (all deterministic, all documented in docs/score-v2.md):
// - circular_flow: for one outside account, the value sent out by
//   the bundle and the value that came back within the window. Flag
//   when the smaller flow is >= 0.1 NEAR and at least half the
//   larger flow returned (returned ratio >= 0.5). A funder that sent
//   much more than it got back is not a round trip.
// - circular_chain: funds that leave a bundle wallet and return
//   through 3–4 hops (simple cycles including a bundle wallet).
//   Flag when the smallest leg is >= 0.1 NEAR — that is the amount
//   that completed the loop. At most 3 cycles reported, in
//   deterministic order.
// - shared_funder: one outside account sent funds to >= 2 distinct
//   bundle wallets — those wallets share a funding source, which is
//   observable onchain; whether they share an owner is not.
// - concentrated_counterparty: one outside account is on >= 80% of
//   the external txs in the window (and there are >= 2). Activity
//   funnelled through a single relationship is not diverse activity.
// - repeated_transfers: the same ordered pair moving the same exact
//   amount >= 3 times in the window.
// - internal_transfers: transfers between the bundle's own wallets
//   in the window. Informational (low): they earn no activity,
//   volume or diversity points, and the link transfer that proves a
//   linked wallet is one of them.
//
// What this module does NOT do:
// - No identity or ownership check: a sock-puppet wallet is
//   indistinguishable from a stranger onchain, so every outside
//   counterparty is labelled UNKNOWN unless it appears in a flagged
//   pattern (then SUSPICIOUS — meaning "appears in a flagged
//   pattern", not "proven malicious"). Bundle wallets are OWN.
// - No score change: flags are advisory. Diversity earned from a
//   flagged counterparty is FLAGGED, not discounted — discounting
//   would change published scores (see docs/score-v2.md). A future
//   score-v3 may discount; v2 only flags.
// - No judgement about intent: a flag says the pattern is present,
//   not why. The detail strings never name an account id, so flags
//   are safe to publish in the public report.
//
// All amounts are yocto BigInts; ratios are integer math. Flag
// details are public-safe (counts and NEAR amounts only, no account
// ids). Flags are sorted by type, so the same evidence always yields
// the same array in the same order.

import { normalizeBundle, unionTxs } from './claims-engine.js';

export const SCORE_DISCLAIMER =
  'This score measures observable onchain financial activity only. It is not a guarantee of repayment, identity, beneficial ownership, or creditworthiness.';

// Thresholds (NEAR, as yocto BigInt where amounts are involved).
export const MIN_CIRCULAR_YOCTO = 10n ** 23n; // 0.1 NEAR
export const CIRCULAR_RETURN_NUM = 1n; // returned ratio >= 1/2
export const CIRCULAR_RETURN_DEN = 2n;
export const CIRCULAR_HIGH_YOCTO = 10n ** 24n; // 1 NEAR
export const CIRCULAR_HIGH_NUM = 9n; // returned ratio >= 9/10
export const CIRCULAR_HIGH_DEN = 10n;
export const REPEAT_MIN_COUNT = 3;
export const REPEAT_HIGH_COUNT = 5;
export const REPEAT_HIGH_YOCTO = 10n * 10n ** 24n; // 10 NEAR
export const CONCENTRATION_NUM = 4n; // top counterparty share >= 4/5
export const CONCENTRATION_DEN = 5n;
export const CONCENTRATION_MIN_TXS = 2;
export const SHARED_FUNDER_MIN_WALLETS = 2;
export const MAX_CYCLE_LENGTH = 4;
export const MAX_CYCLES_REPORTED = 3;
export const MAX_REPEAT_GROUPS_REPORTED = 3;

const NS_PER_DAY = 86400n * 1_000_000_000n;
const YOCTO_PER_NEAR = 10n ** 24n;

// NEAR amount as a short decimal string (up to 6 decimals, trailing
// zeros trimmed). BigInt math only — no floats, so 0.1 + 0.2 style
// errors cannot appear in a flag detail.
export function fmtNear(yocto) {
  const v = BigInt(yocto);
  const whole = v / YOCTO_PER_NEAR;
  const frac = v % YOCTO_PER_NEAR;
  if (frac === 0n) return whole.toString();
  const six = frac.toString().padStart(24, '0').slice(0, 6).replace(/0+$/, '');
  return `${whole.toString()}.${six}`;
}

function inWindowTxs(wallets, txWindowDays, nowNs) {
  if (txWindowDays === undefined || nowNs === undefined || nowNs === null) return null;
  const days = txWindowDays;
  if (typeof days !== 'number' || !Number.isInteger(days) || days < 0) {
    throw new Error('manipulation: txWindowDays must be a non-negative integer number of days');
  }
  const now = BigInt(nowNs);
  const start = now - BigInt(days) * NS_PER_DAY;
  return unionTxs(wallets).filter((tx) => {
    const ts = BigInt(tx.blockTimestampNs);
    return ts >= start && ts <= now && tx.status === 'Success';
  });
}

// Success txs in the window that touch the bundle at all. A disclosed
// tx with no bundle endpoint is ignored (it cannot belong to the
// prover's history).
function bundleTxs(wallets, txWindowDays, nowNs) {
  const all = inWindowTxs(wallets, txWindowDays, nowNs);
  if (all === null) return null;
  const own = new Set(wallets.map((w) => w.account.accountId));
  return all.filter((tx) => own.has(tx.senderId) || own.has(tx.receiverId));
}

export function detectRiskFlags(snapshotOrBundle, { txWindowDays, nowNs } = {}) {
  const wallets = normalizeBundle(snapshotOrBundle);
  const txs = bundleTxs(wallets, txWindowDays, nowNs);
  if (txs === null) return [];
  const own = new Set(wallets.map((w) => w.account.accountId));
  const isExternal = (tx) =>
    (own.has(tx.senderId) || own.has(tx.receiverId)) && (!own.has(tx.senderId) || !own.has(tx.receiverId));
  const flags = [];
  const suspicious = new Set();

  // Internal transfers between the bundle's own wallets.
  const internal = txs.filter((tx) => own.has(tx.senderId) && own.has(tx.receiverId));
  if (internal.length > 0) {
    flags.push({
      type: 'internal_transfers',
      detail: `${internal.length} transfer(s) between the bundle's own wallets in the window; internal transfers earn no activity, volume or diversity points.`,
      severity: 'low',
    });
  }

  const external = txs.filter(isExternal);

  // Circular flow: value that left and came back through one outside
  // account. out/in are the two directions summed; the round trip is
  // the smaller flow, and it only counts when at least half the
  // larger flow returned.
  const flows = new Map();
  for (const tx of external) {
    const other = own.has(tx.senderId) ? tx.receiverId : tx.senderId;
    const entry = flows.get(other) ?? { out: 0n, in: 0n };
    if (own.has(tx.senderId)) entry.out += BigInt(tx.amountYocto);
    else entry.in += BigInt(tx.amountYocto);
    flows.set(other, entry);
  }
  for (const [other, flow] of [...flows.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
    const small = flow.out < flow.in ? flow.out : flow.in;
    const big = flow.out > flow.in ? flow.out : flow.in;
    if (small >= MIN_CIRCULAR_YOCTO && small * CIRCULAR_RETURN_DEN >= big * CIRCULAR_RETURN_NUM) {
      const pct = big === 0n ? 0 : Number((small * 100n) / big);
      const high = small >= CIRCULAR_HIGH_YOCTO || small * CIRCULAR_HIGH_DEN >= big * CIRCULAR_HIGH_NUM;
      flags.push({
        type: 'circular_flow',
        detail: `Value sent to an outside counterparty mostly came back within the window: ${fmtNear(flow.out)} NEAR out, ${fmtNear(flow.in)} NEAR back (${pct}% returned).`,
        severity: high ? 'high' : 'medium',
      });
      suspicious.add(other);
    }
  }

  // Circular chain: simple cycles of 3-4 hops that include a bundle
  // wallet. Enumerated by DFS from every node, canonicalised by
  // rotating to the smallest account id, deduplicated. The amount
  // that completed the loop is the smallest leg.
  {
    const edges = new Map(); // "sender\0receiver" -> total yocto
    const adjacency = new Map(); // sender -> Map(receiver -> total yocto)
    for (const tx of txs) {
      const key = `${tx.senderId}\0${tx.receiverId}`;
      const total = (edges.get(key) ?? 0n) + BigInt(tx.amountYocto);
      edges.set(key, total);
      if (!adjacency.has(tx.senderId)) adjacency.set(tx.senderId, new Map());
      adjacency.get(tx.senderId).set(tx.receiverId, total);
    }
    const nodes = [...new Set([...adjacency.keys(), ...[...adjacency.values()].flatMap((m) => [...m.keys()])])].sort();
    const edgeTotal = (a, b) => edges.get(`${a}\0${b}`) ?? 0n;
    const found = new Map(); // canonical cycle string -> min leg
    if (nodes.length <= 64 && edges.size <= 256) {
      const dfs = (start, current, path, visited) => {
        // A cycle closes when the current node has an edge back to
        // the start. Only 3-4 node cycles count here: 2-node cycles
        // (A -> B -> A) are the circular_flow detector's job.
        if (path.length >= 3 && path.length <= MAX_CYCLE_LENGTH) {
          if (adjacency.get(current)?.has(start)) {
            const cycle = [...path];
            if (cycle.some((n) => own.has(n))) {
              const legs = [...cycle.slice(1), start].map((node, i) => edgeTotal(cycle[i], node));
              const minLeg = legs.reduce((m, v) => (v < m ? v : m), legs[0]);
              if (minLeg >= MIN_CIRCULAR_YOCTO) {
                const smallest = [...cycle].sort()[0];
                const rotated = [...cycle.slice(cycle.indexOf(smallest)), ...cycle.slice(0, cycle.indexOf(smallest))];
                const key = rotated.join('>');
                if (!found.has(key) || minLeg > found.get(key)) found.set(key, minLeg);
              }
            }
          }
        }
        if (path.length >= MAX_CYCLE_LENGTH) return;
        for (const next of [...(adjacency.get(current)?.keys() ?? [])].sort()) {
          if (visited.has(next)) continue;
          visited.add(next);
          path.push(next);
          dfs(start, next, path, visited);
          path.pop();
          visited.delete(next);
        }
      };
      for (const start of nodes) {
        dfs(start, start, [start], new Set([start]));
      }
    }
    const cycles = [...found.entries()]
      .sort((a, b) => (a[1] === b[1] ? (a[0] < b[0] ? -1 : 1) : a[1] > b[1] ? -1 : 1))
      .slice(0, MAX_CYCLES_REPORTED);
    for (const [key, minLeg] of cycles) {
      const hops = key.split('>').length;
      flags.push({
        type: 'circular_chain',
        detail: `Funds left a bundle wallet and returned through a ${hops}-hop chain within the window; at least ${fmtNear(minLeg)} NEAR completed the loop.`,
        severity: minLeg >= CIRCULAR_HIGH_YOCTO ? 'high' : 'medium',
      });
      for (const node of key.split('>')) {
        if (!own.has(node)) suspicious.add(node);
      }
    }
  }

  // Shared funder: one outside account funded >= 2 bundle wallets.
  {
    const funders = new Map(); // outside account -> Set(bundle wallets it sent to)
    for (const tx of txs) {
      if (!own.has(tx.receiverId) || own.has(tx.senderId)) continue;
      const set = funders.get(tx.senderId) ?? new Set();
      set.add(tx.receiverId);
      funders.set(tx.senderId, set);
    }
    for (const [funder, funded] of [...funders.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
      if (funded.size >= SHARED_FUNDER_MIN_WALLETS) {
        flags.push({
          type: 'shared_funder',
          detail: `One outside account sent funds to ${funded.size} wallets in this bundle: those wallets share a funding source.`,
          severity: 'medium',
        });
        suspicious.add(funder);
      }
    }
  }

  // Concentrated counterparty: one outside account on >= 80% of the
  // external txs (with at least 2 external txs).
  {
    const counts = new Map();
    for (const tx of external) {
      const other = own.has(tx.senderId) ? tx.receiverId : tx.senderId;
      counts.set(other, (counts.get(other) ?? 0) + 1);
    }
    if (external.length >= CONCENTRATION_MIN_TXS) {
      const ranked = [...counts.entries()].sort((a, b) => b[1] - a[1] || (a[0] < b[0] ? -1 : 1));
      const [top, topCount] = ranked[0];
      if (BigInt(topCount) * CONCENTRATION_DEN >= BigInt(external.length) * CONCENTRATION_NUM) {
        const pct = Math.floor((topCount * 100) / external.length);
        flags.push({
          type: 'concentrated_counterparty',
          detail: `${pct}% of external transactions in the window (${topCount} of ${external.length}) are with a single outside counterparty.`,
          severity: 'medium',
        });
        suspicious.add(top);
      }
    }
  }

  // Repeated transfers: the same ordered pair moving the same exact
  // amount >= 3 times.
  {
    const groups = new Map();
    for (const tx of txs) {
      const key = `${tx.senderId}\0${tx.receiverId}\0${tx.amountYocto}`;
      const entry = groups.get(key) ?? { count: 0, total: 0n };
      entry.count += 1;
      entry.total += BigInt(tx.amountYocto);
      groups.set(key, entry);
    }
    const repeated = [...groups.entries()]
      .filter(([, g]) => g.count >= REPEAT_MIN_COUNT)
      .sort((a, b) => b[1].count - a[1].count || (b[1].total > a[1].total ? 1 : b[1].total < a[1].total ? -1 : 0) || (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
      .slice(0, MAX_REPEAT_GROUPS_REPORTED);
    for (const [key, group] of repeated) {
      const [, , amountYocto] = key.split('\0');
      flags.push({
        type: 'repeated_transfers',
        detail: `The same amount (${fmtNear(amountYocto)} NEAR) moved between the same two accounts ${group.count} times in the window (total ${fmtNear(group.total)} NEAR).`,
        severity: group.count >= REPEAT_HIGH_COUNT || group.total >= REPEAT_HIGH_YOCTO ? 'high' : 'medium',
      });
      const [sender, receiver] = key.split('\0');
      if (!own.has(sender)) suspicious.add(sender);
      if (!own.has(receiver)) suspicious.add(receiver);
    }
  }

  flags.sort((a, b) => (a.type < b.type ? -1 : a.type > b.type ? 1 : a.detail < b.detail ? -1 : 1));
  return { flags, suspicious };
}

// Label every counterparty that appears in the window's txs:
// - 'own': one of the bundle's own wallets.
// - 'suspicious': an outside account involved in a medium/high flag.
// - 'unknown': every other outside account. No identity or ownership
//   evidence exists for it, so independence is NOT assumed.
// Sorted by account, so the same evidence always yields the same list.
export function labelCounterparties(snapshotOrBundle, { txWindowDays, nowNs } = {}) {
  const wallets = normalizeBundle(snapshotOrBundle);
  const txs = bundleTxs(wallets, txWindowDays, nowNs);
  if (txs === null) return [];
  const own = new Set(wallets.map((w) => w.account.accountId));
  const { suspicious } = detectRiskFlags(snapshotOrBundle, { txWindowDays, nowNs });
  const accounts = new Set();
  for (const tx of txs) {
    accounts.add(tx.senderId);
    accounts.add(tx.receiverId);
  }
  return [...accounts].sort().map((account) => ({
    account,
    label: own.has(account) ? 'own' : suspicious.has(account) ? 'suspicious' : 'unknown',
  }));
}

// Public-safe counts of counterparty labels (no account ids): the
// form that may appear in the public report.
export function counterpartySummary(labels) {
  const summary = { own: 0, unknown: 0, suspicious: 0 };
  for (const entry of labels) {
    if (entry.label === 'own') summary.own += 1;
    else if (entry.label === 'suspicious') summary.suspicious += 1;
    else summary.unknown += 1;
  }
  return summary;
}
