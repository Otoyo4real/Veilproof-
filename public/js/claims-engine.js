// VeilProof claims engine — PURE deterministic functions.
// No network, no clock: the caller passes `nowNs` explicitly so every
// claim is reproducible from (snapshot, policy, nowNs) alone.
// Amounts are yocto strings compared with BigInt, never with floats.
// The engine never invents or rounds values; a claim is only as true as
// the snapshot it was given (the snapshot's data comes from the chain).
//
// Window rule (all windowed claims): a tx is in the window when
//   nowNs - days * 86400e9 <= blockTimestampNs <= nowNs
// i.e. both edges are INCLUSIVE: a tx exactly at the window start counts,
// a tx 1ns before it does not, and a tx after `nowNs` does not.
//
// `passed` semantics per claim:
// - balance_at_least / staked_at_least: value >= threshold.
// - tx_count_in_window (standalone): at least one Success tx in the window.
//   evaluateClaims overrides this with the policy's minTxCount when set.
// - volume_in_window (standalone): summed volume > 0. evaluateClaims
//   overrides this with the policy's minVolumeYocto when set.
// - no_failed_txs_in_window: zero Failure txs in the window.
// - aggregate_balance_at_least: SUM of balances across all wallets
//   in the bundle >= threshold. A single wallet's balance proves
//   little; an agent's treasury is usually spread across wallets.
// - aggregate_tx_count_in_window / aggregate_volume_in_window: the
//   same as tx_count/volume, but over the UNION of all wallets' txs
//   (each tx counted once, even when it moves between two of the
//   prover's own wallets).
// - sustained_balance_at_least: the LOWEST sampled balance across the
//   sampled window >= threshold. Samples are recorded balance readings
//   at past block heights (see onchain.sampleBalanceHistory); a flash
//   deposit an hour before the report does not pass this, a balance
//   held for weeks does. Value is the minimum sampled SUM across
//   wallets (single wallet: its own minimum).
// - time_weighted_balance_at_least: the AVERAGE sampled balance
//   across the sampled window >= threshold. Value is the integer
//   mean of the sampled sums (yocto string).
//
// A bundle is { wallets: [snapshot, ...] }; a single snapshot is
// treated as a one-wallet bundle. Every wallet in a bundle must pass
// requireSnapshot. Aggregate and sustained claims need the bundle;
// the five original claims run on the PRIMARY wallet only (wallets[0])
// so old single-wallet reports evaluate exactly as before.

const NS_PER_DAY = 86400n * 1_000_000_000n;

function toBigInt(value, label) {
  try {
    const b = BigInt(value);
    if (b < 0n) throw new Error('negative');
    return b;
  } catch {
    throw new Error(`claims-engine: ${label} must be a non-negative integer, got ${JSON.stringify(value)}`);
  }
}

function toDays(days, label) {
  if (typeof days !== 'number' || !Number.isInteger(days) || days < 0) {
    throw new Error(`claims-engine: ${label} must be a non-negative integer number of days, got ${JSON.stringify(days)}`);
  }
  return days;
}

function requireSnapshot(snapshot) {
  if (!snapshot || typeof snapshot !== 'object' || !snapshot.account || !Array.isArray(snapshot.txs)) {
    throw new Error('claims-engine: snapshot must have { account, txs }');
  }
  toBigInt(snapshot.account.amount, 'snapshot.account.amount');
  toBigInt(snapshot.account.locked, 'snapshot.account.locked');
  for (const tx of snapshot.txs) {
    toBigInt(tx.amountYocto, 'tx.amountYocto');
    toBigInt(tx.blockTimestampNs, 'tx.blockTimestampNs');
  }
  if (snapshot.balanceSamples !== undefined) {
    if (!Array.isArray(snapshot.balanceSamples)) {
      throw new Error('claims-engine: snapshot.balanceSamples must be an array when present');
    }
    for (const s of snapshot.balanceSamples) {
      if (!s || typeof s !== 'object') throw new Error('claims-engine: balanceSamples entries must be objects');
      toBigInt(s.amount, 'balanceSample.amount');
      if (!Number.isInteger(s.blockHeight) || s.blockHeight < 0) {
        throw new Error('claims-engine: balanceSample.blockHeight must be a non-negative integer');
      }
    }
  }
}

// A snapshot, or a bundle of them. Returns the wallets array.
// A bundle with zero wallets is a caller error.
export function normalizeBundle(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new Error('claims-engine: snapshot or bundle must be an object');
  }
  const wallets = Array.isArray(input.wallets) ? input.wallets : [input];
  if (wallets.length === 0) {
    throw new Error('claims-engine: bundle must contain at least one wallet snapshot');
  }
  wallets.forEach(requireSnapshot);
  return wallets;
}

// Union of all wallets' txs, deduplicated by hash, sorted by hash.
// A transfer between two of the prover's own wallets appears in both
// snapshots; the union counts it once.
export function unionTxs(wallets) {
  const byHash = new Map();
  for (const wallet of wallets) {
    for (const tx of wallet.txs) {
      if (!byHash.has(tx.hash)) byHash.set(tx.hash, tx);
    }
  }
  return [...byHash.values()].sort((a, b) => (a.hash < b.hash ? -1 : a.hash > b.hash ? 1 : 0));
}

// Sum of current balances across wallets (yocto BigInt).
export function aggregateBalance(wallets) {
  return wallets.reduce((sum, w) => sum + toBigInt(w.account.amount, 'snapshot.account.amount'), 0n);
}

// Sum of staked (locked) balances across wallets (yocto BigInt).
export function aggregateStaked(wallets) {
  return wallets.reduce((sum, w) => sum + toBigInt(w.account.locked, 'snapshot.account.locked'), 0n);
}

// Per-sample-point sums of sampled balances across wallets, aligned
// by blockHeight. Every wallet must carry balanceSamples, and the
// sample heights must match exactly across wallets (they do when the
// samples were taken in one run from one current height). Returns
// [{ blockHeight, amount }] sorted by height ascending (oldest first).
// Throws when samples are missing or misaligned — a sustained claim
// without aligned samples is a policy error, not a silent pass.
export function sampleSums(wallets) {
  for (const w of wallets) {
    if (!Array.isArray(w.balanceSamples) || w.balanceSamples.length === 0) {
      throw new Error('claims-engine: sustained/time-weighted claims need balanceSamples on every wallet');
    }
  }
  const heights = wallets[0].balanceSamples.map((s) => s.blockHeight);
  for (const w of wallets.slice(1)) {
    const mine = w.balanceSamples.map((s) => s.blockHeight);
    if (mine.length !== heights.length || mine.some((h, i) => h !== heights[i])) {
      throw new Error('claims-engine: balanceSamples block heights must match across wallets');
    }
  }
  return heights.map((blockHeight, i) => ({
    blockHeight,
    amount: wallets.reduce((sum, w) => sum + toBigInt(w.balanceSamples[i].amount, 'balanceSample.amount'), 0n),
  }));
}

// Verified txs whose block timestamp falls inside the window.
function txsInWindow(txs, days, nowNs) {
  const now = toBigInt(nowNs, 'nowNs');
  const start = now - BigInt(toDays(days, 'days')) * NS_PER_DAY;
  return txs.filter((tx) => {
    const ts = toBigInt(tx.blockTimestampNs, 'tx.blockTimestampNs');
    return ts >= start && ts <= now;
  });
}

export function balanceAtLeast(snapshot, amountYocto) {
  requireSnapshot(snapshot);
  const threshold = toBigInt(amountYocto, 'amountYocto');
  const value = toBigInt(snapshot.account.amount, 'snapshot.account.amount');
  return { id: 'balance_at_least', passed: value >= threshold, value: value.toString(), threshold: threshold.toString() };
}

export function stakedAtLeast(snapshot, amountYocto) {
  requireSnapshot(snapshot);
  const threshold = toBigInt(amountYocto, 'amountYocto');
  const value = toBigInt(snapshot.account.locked, 'snapshot.account.locked');
  return { id: 'staked_at_least', passed: value >= threshold, value: value.toString(), threshold: threshold.toString() };
}

export function txCountInWindow(snapshot, days, nowNs) {
  requireSnapshot(snapshot);
  const count = txsInWindow(snapshot.txs, days, nowNs).filter((tx) => tx.status === 'Success').length;
  return { id: 'tx_count_in_window', passed: count >= 1, value: count, threshold: toDays(days, 'days') };
}

export function volumeInWindow(snapshot, days, nowNs) {
  requireSnapshot(snapshot);
  const accountId = snapshot.account.accountId;
  let sum = 0n;
  for (const tx of txsInWindow(snapshot.txs, days, nowNs)) {
    if (tx.status !== 'Success') continue;
    // Only the account's own flow counts, and each tx is counted once
    // even when sender and receiver are both the account (self-transfer).
    if (tx.senderId !== accountId && tx.receiverId !== accountId) continue;
    sum += toBigInt(tx.amountYocto, 'tx.amountYocto');
  }
  return { id: 'volume_in_window', passed: sum > 0n, value: sum.toString(), threshold: toDays(days, 'days') };
}

export function noFailedTxsInWindow(snapshot, days, nowNs) {
  requireSnapshot(snapshot);
  const failed = txsInWindow(snapshot.txs, days, nowNs).filter((tx) => tx.status === 'Failure').length;
  return { id: 'no_failed_txs_in_window', passed: failed === 0, value: failed, threshold: toDays(days, 'days') };
}

export function aggregateBalanceAtLeast(wallets, amountYocto) {
  const threshold = toBigInt(amountYocto, 'amountYocto');
  const value = aggregateBalance(wallets);
  return { id: 'aggregate_balance_at_least', passed: value >= threshold, value: value.toString(), threshold: threshold.toString() };
}

export function aggregateTxCountInWindow(wallets, days, nowNs) {
  const count = txsInWindow(unionTxs(wallets), days, nowNs).filter((tx) => tx.status === 'Success').length;
  return { id: 'aggregate_tx_count_in_window', passed: count >= 1, value: count, threshold: toDays(days, 'days') };
}

export function aggregateVolumeInWindow(wallets, days, nowNs) {
  const ids = new Set(wallets.map((w) => w.account.accountId));
  let sum = 0n;
  for (const tx of txsInWindow(unionTxs(wallets), days, nowNs)) {
    if (tx.status !== 'Success') continue;
    if (!ids.has(tx.senderId) && !ids.has(tx.receiverId)) continue;
    sum += toBigInt(tx.amountYocto, 'tx.amountYocto');
  }
  return { id: 'aggregate_volume_in_window', passed: sum > 0n, value: sum.toString(), threshold: toDays(days, 'days') };
}

export function sustainedBalanceAtLeast(wallets, amountYocto) {
  const threshold = toBigInt(amountYocto, 'amountYocto');
  const sums = sampleSums(wallets);
  const min = sums.reduce((m, s) => (s.amount < m ? s.amount : m), sums[0].amount);
  return { id: 'sustained_balance_at_least', passed: min >= threshold, value: min.toString(), threshold: threshold.toString() };
}

export function timeWeightedBalanceAtLeast(wallets, amountYocto) {
  const threshold = toBigInt(amountYocto, 'amountYocto');
  const sums = sampleSums(wallets);
  const total = sums.reduce((acc, s) => acc + s.amount, 0n);
  const avg = total / BigInt(sums.length);
  return { id: 'time_weighted_balance_at_least', passed: avg >= threshold, value: avg.toString(), threshold: threshold.toString() };
}

// Evaluate the claims present in a policy. Only the claims the policy
// names are evaluated, in fixed order (balance, staked, tx count, volume,
// no-failed, then the aggregate and sustained/time-weighted claims).
// A windowed claim with a policy threshold is passed only when the
// measured value meets that threshold; a minTxCount/minVolumeYocto
// without its window field is a policy error, not a silent default.
// Returns { claims, allPassed }. An empty policy evaluates nothing and
// allPassed is true (vacuous).
export function evaluateClaims(snapshotOrBundle, policy = {}, nowNs) {
  const wallets = normalizeBundle(snapshotOrBundle);
  const snapshot = wallets[0];
  if (policy === null || typeof policy !== 'object' || Array.isArray(policy)) {
    throw new Error('claims-engine: policy must be an object');
  }
  const claims = [];
  if (policy.balanceAtLeastYocto !== undefined) {
    claims.push(balanceAtLeast(snapshot, policy.balanceAtLeastYocto));
  }
  if (policy.stakedAtLeastYocto !== undefined) {
    claims.push(stakedAtLeast(snapshot, policy.stakedAtLeastYocto));
  }
  if (policy.minTxCount !== undefined) {
    if (policy.txWindowDays === undefined) {
      throw new Error('claims-engine: policy.minTxCount requires policy.txWindowDays');
    }
    const counted = txCountInWindow(snapshot, policy.txWindowDays, nowNs);
    const min = toBigInt(policy.minTxCount, 'policy.minTxCount');
    claims.push({ ...counted, passed: BigInt(counted.value) >= min });
  }
  if (policy.minVolumeYocto !== undefined) {
    if (policy.volumeWindowDays === undefined) {
      throw new Error('claims-engine: policy.minVolumeYocto requires policy.volumeWindowDays');
    }
    const vol = volumeInWindow(snapshot, policy.volumeWindowDays, nowNs);
    const min = toBigInt(policy.minVolumeYocto, 'policy.minVolumeYocto');
    claims.push({ ...vol, passed: BigInt(vol.value) >= min });
  }
  if (policy.noFailedWindowDays !== undefined) {
    claims.push(noFailedTxsInWindow(snapshot, policy.noFailedWindowDays, nowNs));
  }
  if (policy.aggregateBalanceAtLeastYocto !== undefined) {
    claims.push(aggregateBalanceAtLeast(wallets, policy.aggregateBalanceAtLeastYocto));
  }
  if (policy.aggregateMinTxCount !== undefined) {
    if (policy.aggregateTxWindowDays === undefined) {
      throw new Error('claims-engine: policy.aggregateMinTxCount requires policy.aggregateTxWindowDays');
    }
    const counted = aggregateTxCountInWindow(wallets, policy.aggregateTxWindowDays, nowNs);
    const min = toBigInt(policy.aggregateMinTxCount, 'policy.aggregateMinTxCount');
    claims.push({ ...counted, passed: BigInt(counted.value) >= min });
  }
  if (policy.aggregateMinVolumeYocto !== undefined) {
    if (policy.aggregateVolumeWindowDays === undefined) {
      throw new Error('claims-engine: policy.aggregateMinVolumeYocto requires policy.aggregateVolumeWindowDays');
    }
    const vol = aggregateVolumeInWindow(wallets, policy.aggregateVolumeWindowDays, nowNs);
    const min = toBigInt(policy.aggregateMinVolumeYocto, 'policy.aggregateMinVolumeYocto');
    claims.push({ ...vol, passed: BigInt(vol.value) >= min });
  }
  if (policy.sustainedBalanceAtLeastYocto !== undefined) {
    claims.push(sustainedBalanceAtLeast(wallets, policy.sustainedBalanceAtLeastYocto));
  }
  if (policy.timeWeightedBalanceAtLeastYocto !== undefined) {
    claims.push(timeWeightedBalanceAtLeast(wallets, policy.timeWeightedBalanceAtLeastYocto));
  }
  return { claims, allPassed: claims.every((c) => c.passed) };
}
