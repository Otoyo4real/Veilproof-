// VeilProof balance-sampling evidence — PURE deterministic functions.
//
// A sampled balance is a point-in-time reading: the balance at one
// block height, read from the chain. A set of samples proves the
// balance AT those blocks and nothing about the blocks between them.
// Funds moved out between two samples and back before the next one
// are invisible to sampling. This module is the honest record of
// what was actually observed: which heights were read, how far apart
// they are, when they happened, what the lowest observed balance was,
// and whether any requested reading is missing.
//
// describeSampling(snapshotOrBundle, requested) turns a snapshot (or
// bundle) into that record. Everything it returns is derived from
// the snapshot's balanceSamples (amounts + heights, which the data
// hash pins) plus, for timestamps, the block timestamps stored on
// the samples or — when those are absent — a deterministic estimate
// from the newest disclosed tx (1 second per block). Nothing here
// touches the network and nothing here uses the clock, so any
// verifier holding the same disclosure package recomputes the exact
// same record.
//
// Thresholds (documented, deterministic — see docs/sampling.md):
// - WIDE_INTERVAL_BLOCKS = 3600: NEAR makes about 1 block per
//   second, so 3600 blocks is about 1 hour. A gap wider than that
//   means the balance was unobserved for over an hour.
// - MIN_MEANINGFUL_SAMPLES = 4: fewer than 4 readings over the
//   window is too thin to call a balance "sustained".
// Either condition raises wideIntervalWarning.
//
// Completeness:
// - 'complete': every requested height was read on every wallet,
//   and the read heights form a uniform grid (or the request is
//   unknown and the grid is uniform).
// - 'partial': some requested height is missing (listed in
//   missingHeights), or fewer readings came back than were
//   requested, or a height is present on some wallets but not all.
// - 'none': no usable sample points at all.
//
// Missing heights the prover did not record are inferred from the
// grid only when the gaps are exact multiples of the smallest gap
// (a 2x gap at step 900 means exactly one height is missing in the
// middle). An irregular grid with no recorded request cannot prove
// a height is missing, and this module does not pretend otherwise.
//
// Language rule: samples are "observed", never "maintained" or
// "guaranteed". The limitation string in every record says so.

import { normalizeBundle, unionTxs } from './claims-engine.js';

export const WIDE_INTERVAL_BLOCKS = 3600;
export const MIN_MEANINGFUL_SAMPLES = 4;

export const SAMPLING_LIMITATION =
  'Balance samples are point-in-time readings only. They show the balance at the sampled blocks; they do not prove the balance was held continuously between samples.';

const NS_PER_BLOCK_ESTIMATE = 1_000_000_000n;

function toBigInt(value, label) {
  try {
    const b = BigInt(value);
    if (b < 0n) throw new Error('negative');
    return b;
  } catch {
    throw new Error(`sampling: ${label} must be a non-negative integer, got ${JSON.stringify(value)}`);
  }
}

function sampleTimestamp(value, label) {
  if (value === undefined || value === null) return null;
  return toBigInt(value, label).toString();
}

// The newest disclosed tx (by block height) is the anchor for
// estimated sample timestamps: timestamp(h) = anchorTs +
// (h - anchorHeight) * 1s. NEAR block time is not exactly 1 second,
// so an estimate is labelled 'estimated', never 'rpc'.
function estimateAnchor(wallets) {
  const txs = unionTxs(wallets);
  let anchor = null;
  for (const tx of txs) {
    if (!Number.isInteger(tx.blockHeight)) continue;
    const ts = sampleTimestamp(tx.blockTimestampNs, 'tx.blockTimestampNs');
    if (ts === null) continue;
    if (anchor === null || tx.blockHeight > anchor.blockHeight) {
      anchor = { blockHeight: tx.blockHeight, timestampNs: BigInt(ts) };
    }
  }
  return anchor;
}

export function describeSampling(snapshotOrBundle, requested = {}) {
  const wallets = normalizeBundle(snapshotOrBundle);
  const req = requested && typeof requested === 'object' && !Array.isArray(requested) ? requested : {};
  // Request context recorded at fetch time (see onchain.js): how many
  // readings were asked for, and which heights the node could not
  // serve. When the caller does not supply it, fall back to what the
  // snapshots themselves recorded; without either, the grid is the
  // only signal. A prover-supplied request count is context, not
  // proof — the grid check below is the independent signal.
  let samplesRequested = null;
  let recordedMissing = [];
  if (Number.isInteger(req.samplesRequested) && req.samplesRequested >= 0) {
    samplesRequested = req.samplesRequested;
  } else if (Number.isInteger(wallets[0]?.sampling?.samplesRequested) && wallets[0].sampling.samplesRequested >= 0) {
    samplesRequested = wallets[0].sampling.samplesRequested;
  }
  if (Array.isArray(req.missingHeights)) {
    recordedMissing = req.missingHeights;
  } else if (Array.isArray(wallets[0]?.sampling?.missingHeights)) {
    recordedMissing = wallets[0].sampling.missingHeights;
  }
  const requestedHeights = Array.isArray(req.requestedHeights) ? req.requestedHeights : [];

  // Per-wallet samples: height -> { amount, blockTimestampNs? }.
  const perWallet = wallets.map((w) => {
    const map = new Map();
    for (const s of Array.isArray(w.balanceSamples) ? w.balanceSamples : []) {
      if (!Number.isInteger(s.blockHeight) || s.blockHeight < 0) {
        throw new Error('sampling: balanceSample.blockHeight must be a non-negative integer');
      }
      const amount = toBigInt(s.amount, 'balanceSample.amount');
      const timestampNs = sampleTimestamp(s.blockTimestampNs, 'balanceSample.blockTimestampNs');
      // A duplicated height on one wallet is a malformed snapshot:
      // the same block cannot hold two balances.
      if (map.has(s.blockHeight)) {
        throw new Error(`sampling: duplicate balance sample at block height ${s.blockHeight}`);
      }
      map.set(s.blockHeight, { amount, blockTimestampNs: timestampNs });
    }
    return map;
  });

  const unionHeights = [...new Set(perWallet.flatMap((m) => [...m.keys()]))].sort((a, b) => a - b);
  // A height counts only when every wallet was read there; a sum over
  // a height one wallet missed would understate the balance.
  const completeHeights = unionHeights.filter((h) => perWallet.every((m) => m.has(h)));

  // Missing heights: requested but never read, read on some wallets
  // but not all, recorded missing at fetch time, and heights implied
  // by the grid (a gap that is an exact multiple of the smallest gap
  // hides whole steps in the middle).
  const missing = new Set();
  for (const h of requestedHeights) {
    if (!unionHeights.includes(h)) missing.add(h);
  }
  for (const h of unionHeights) {
    if (!completeHeights.includes(h)) missing.add(h);
  }
  for (const h of recordedMissing) {
    if (Number.isInteger(h) && h >= 0) missing.add(h);
  }
  if (completeHeights.length >= 2) {
    const gaps = [];
    for (let i = 1; i < completeHeights.length; i += 1) gaps.push(completeHeights[i] - completeHeights[i - 1]);
    const step = Math.min(...gaps);
    if (step > 0) {
      for (let i = 1; i < completeHeights.length; i += 1) {
        const gap = completeHeights[i] - completeHeights[i - 1];
        if (gap % step === 0 && gap > step) {
          for (let k = 1; k < gap / step; k += 1) missing.add(completeHeights[i - 1] + k * step);
        }
      }
    }
  }
  const missingHeights = [...missing].sort((a, b) => a - b);

  // Interval: the widest unsampled stretch between two complete
  // readings. Null when fewer than two complete readings exist.
  let intervalBlocks = null;
  if (completeHeights.length >= 2) {
    intervalBlocks = 0;
    for (let i = 1; i < completeHeights.length; i += 1) {
      intervalBlocks = Math.max(intervalBlocks, completeHeights[i] - completeHeights[i - 1]);
    }
  }

  // Lowest observed sampled balance: the minimum, over complete
  // heights, of the SUMMED balance across wallets (the same value
  // the sustained-balance claim evaluates).
  let lowestObservedSampledBalance = null;
  if (completeHeights.length > 0) {
    let min = null;
    for (const h of completeHeights) {
      const sum = perWallet.reduce((acc, m) => acc + m.get(h).amount, 0n);
      if (min === null || sum < min) min = sum;
    }
    lowestObservedSampledBalance = min.toString();
  }

  // Sample timestamps: the block timestamp stored on the sample when
  // present ('rpc'), otherwise the deterministic estimate from the
  // newest disclosed tx ('estimated'). No stored timestamp and no
  // anchor at all means no timestamps can be given.
  let sampleTimestamps = null;
  let timestampSource = 'unavailable';
  if (completeHeights.length > 0) {
    const anchor = estimateAnchor(wallets);
    const entries = [];
    let allRpc = true;
    let anyTimestamp = false;
    for (const h of completeHeights) {
      // The block timestamp is the same block for every wallet; take
      // the first stored one across wallets, if any.
      let stored = null;
      for (const m of perWallet) {
        if (m.get(h).blockTimestampNs !== null) {
          stored = m.get(h).blockTimestampNs;
          break;
        }
      }
      if (stored !== null) {
        entries.push({ blockHeight: h, timestampNs: stored, source: 'rpc' });
        anyTimestamp = true;
      } else if (anchor !== null) {
        const estimated = (anchor.timestampNs + BigInt(h - anchor.blockHeight) * NS_PER_BLOCK_ESTIMATE).toString();
        entries.push({ blockHeight: h, timestampNs: estimated, source: 'estimated' });
        allRpc = false;
        anyTimestamp = true;
      } else {
        entries.push({ blockHeight: h, timestampNs: null, source: 'unavailable' });
        allRpc = false;
      }
    }
    if (anyTimestamp) {
      sampleTimestamps = entries;
      timestampSource = allRpc ? 'rpc' : 'estimated';
    } else {
      sampleTimestamps = null;
      timestampSource = 'unavailable';
    }
  }

  const sampleCount = completeHeights.length;
  let completeness = 'none';
  if (sampleCount > 0) {
    completeness =
      missingHeights.length > 0 || (samplesRequested !== null && sampleCount < samplesRequested) ? 'partial' : 'complete';
  }

  // Wide-interval warning: the interval is too wide to be meaningful,
  // or there are too few readings to call a balance sustained.
  let wideIntervalWarning = null;
  if (sampleCount > 0) {
    const tooFew = sampleCount < MIN_MEANINGFUL_SAMPLES;
    const tooWide = intervalBlocks !== null && intervalBlocks > WIDE_INTERVAL_BLOCKS;
    if (tooFew || tooWide) {
      const reason = tooFew && tooWide ? 'both' : tooFew ? 'too_few_samples' : 'interval_too_wide';
      const message =
        reason === 'both'
          ? `Only ${sampleCount} balance sample(s) over the window with gaps up to ${intervalBlocks} blocks: the balance was observed too rarely to call it sustained.`
          : reason === 'too_few_samples'
            ? `Only ${sampleCount} balance sample(s) over the window (fewer than ${MIN_MEANINGFUL_SAMPLES}): too few readings to call the balance sustained.`
            : `Balance samples are up to ${intervalBlocks} blocks apart (over ${WIDE_INTERVAL_BLOCKS} blocks, about 1 hour): the balance was unobserved for over an hour at a stretch.`;
      wideIntervalWarning = {
        reason,
        intervalBlocks,
        thresholdBlocks: WIDE_INTERVAL_BLOCKS,
        sampleCount,
        minSamples: MIN_MEANINGFUL_SAMPLES,
        message,
      };
    }
  }

  const windowHours =
    typeof wallets[0]?.balanceSampleWindowHours === 'number' ? wallets[0].balanceSampleWindowHours : null;

  return {
    windowHours,
    intervalBlocks,
    sampleCount,
    oldestBlock: sampleCount > 0 ? completeHeights[0] : null,
    newestBlock: sampleCount > 0 ? completeHeights[completeHeights.length - 1] : null,
    sampleTimestamps,
    timestampSource,
    lowestObservedSampledBalance,
    completeness,
    missingHeights,
    samplesRequested,
    wideIntervalWarning,
    limitation: SAMPLING_LIMITATION,
  };
}
