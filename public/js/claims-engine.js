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
}

// Verified txs whose block timestamp falls inside the window.
function txsInWindow(snapshot, days, nowNs) {
  const now = toBigInt(nowNs, 'nowNs');
  const start = now - BigInt(toDays(days, 'days')) * NS_PER_DAY;
  return snapshot.txs.filter((tx) => {
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
  const count = txsInWindow(snapshot, days, nowNs).filter((tx) => tx.status === 'Success').length;
  return { id: 'tx_count_in_window', passed: count >= 1, value: count, threshold: toDays(days, 'days') };
}

export function volumeInWindow(snapshot, days, nowNs) {
  requireSnapshot(snapshot);
  const accountId = snapshot.account.accountId;
  let sum = 0n;
  for (const tx of txsInWindow(snapshot, days, nowNs)) {
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
  const failed = txsInWindow(snapshot, days, nowNs).filter((tx) => tx.status === 'Failure').length;
  return { id: 'no_failed_txs_in_window', passed: failed === 0, value: failed, threshold: toDays(days, 'days') };
}

// Evaluate the claims present in a policy. Only the claims the policy
// names are evaluated, in fixed order (balance, staked, tx count, volume,
// no-failed). A windowed claim with a policy threshold is passed only when
// the measured value meets that threshold; a minTxCount/minVolumeYocto
// without its window field is a policy error, not a silent default.
// Returns { claims, allPassed }. An empty policy evaluates nothing and
// allPassed is true (vacuous).
export function evaluateClaims(snapshot, policy = {}, nowNs) {
  requireSnapshot(snapshot);
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
  return { claims, allPassed: claims.every((c) => c.passed) };
}
