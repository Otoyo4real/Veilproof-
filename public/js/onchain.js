// VeilProof onchain ingestion — BROWSER mirror of src/onchain.js.
//
// NEAR testnet RPC reads only. No keys, no signing, no secrets. The
// chain is the source of truth: a verifier can re-fetch everything
// here and reproduce the same facts.
//
// Same RPC behaviour as the Node module (verified 2026-11-06):
// - `tx` expects the hash as BASE58 (hex is rejected with a parse error).
// - A well-formed but absent tx returns HANDLER_ERROR / TIMEOUT_ERROR
//   with cause NOT_OBSERVED, or HTTP 408. verifyTx maps exactly those
//   errors to null, and throws on every other RPC error.
// - Neither `tx` nor `EXPERIMENTAL_tx_status` returns block height or
//   timestamp; verifyTx fetches the block by
//   transaction_outcome.block_hash to get both.
// - Regular nodes prune old transactions (a few epochs). Claims must
//   use recent txs.
//
// Only the hash primitive differs: Web Crypto (async) instead of
// node:crypto, so computeDataHash and fetchAccountSnapshot are async
// here. TWO PATHS, kept in sync by the parity test in
// test/frontend-parity.test.mjs. Keep the two in sync.

import { sha256Hex } from './crypto.js';
import { describeSampling } from './sampling.js';

export const NEAR_TESTNET_RPC = 'https://rpc.testnet.near.org';

// Fallback testnet RPC endpoints, tried in order when the primary
// cannot be reached. Some networks block or fail one node and not the
// other; a call that fails on every endpoint is a network problem on
// the user's side, not a data problem.
const NEAR_TESTNET_RPCS = [
  NEAR_TESTNET_RPC,
  'https://archival-rpc.testnet.near.org',
];

const BASE58_RE = /^[1-9A-HJ-NP-Za-km-z]{43,44}$/;

class RpcError extends Error {
  constructor(message, rpcError) {
    super(message);
    this.name = 'RpcError';
    this.rpcError = rpcError;
  }
}

// One JSON-RPC call. Retries ONCE per endpoint on network errors only
// (fetch throwing, HTTP failure, local timeout), then tries the next
// endpoint. RPC-level errors are thrown immediately.
async function rpcCall(method, params, { timeoutMs = 30000, retries = 1 } = {}) {
  let lastError;
  for (const rpcUrl of NEAR_TESTNET_RPCS) {
    for (let attempt = 0; attempt <= retries; attempt += 1) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const res = await fetch(rpcUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ jsonrpc: '2.0', id: `${method}-${Date.now()}-${attempt}`, method, params }),
          signal: controller.signal,
        });
        clearTimeout(timer);
        // HTTP 408 from the tx-lookup endpoints is the node's lookup timeout
        // in HTTP form (the same condition the JSON API reports as
        // TIMEOUT_ERROR / NOT_OBSERVED). It is surfaced with its status so
        // verifyTx can classify it as "not observed" instead of retrying it
        // as a network error. Other HTTP failures are network errors.
        if (!res.ok) {
          const err = new Error(`NEAR RPC HTTP ${res.status} on ${method}`);
          err.httpStatus = res.status;
          throw err;
        }
        const json = await res.json();
        if (json.error) {
          throw new RpcError(`NEAR RPC ${method} failed: ${json.error.message || json.error.name || 'unknown error'}`, json.error);
        }
        return json.result;
      } catch (err) {
        clearTimeout(timer);
        if (err instanceof RpcError) throw err;
        // An HTTP 408 is a lookup timeout, not a transient blip: retrying
        // it just burns another timeout. Surface it for classification.
        if (err.httpStatus === 408) throw err;
        lastError = err;
        if (attempt < retries) continue;
        // This endpoint is unreachable; try the next one.
        break;
      }
    }
  }
  throw new Error(`NEAR RPC ${method} network error: ${lastError ? lastError.message : 'unreachable'}. Check your connection and try again.`);
}

// True when the RPC says "this transaction was never observed".
// That is the only error verifyTx maps to null; everything else throws.
// Two surface forms of the same condition:
// - JSON: HANDLER_ERROR / TIMEOUT_ERROR with cause NOT_OBSERVED.
// - HTTP 408 on a tx lookup (the node's lookup timeout in HTTP form).
function isNotObservedError(err) {
  const rpc = err?.rpcError ?? err;
  return rpc?.cause?.name === 'TIMEOUT_ERROR' || rpc?.cause?.info?.cause === 'NOT_OBSERVED' || err?.httpStatus === 408;
}

// Canonical JSON: object keys sorted recursively, so the same payload
// always hashes the same way regardless of key insertion order.
// (Local copy of the canonicalisation in src/onchain.js; the shared
// canonicalJson in ./canonical.js serialises the same way.)
function canonicalize(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalize(value[k])}`).join(',')}}`;
}

// SHA-256 of the canonical snapshot payload. Only these fields are hashed:
// accountId, amount, locked, and the verified txs sorted by hash.
// Nothing else (no block height, no timestamps of the fetch) is included,
// so any verifier re-fetching the same facts reproduces the same hash.
export async function computeDataHash(accountId, amount, locked, txs) {
  const sortedTxs = [...txs].sort((a, b) => (a.hash < b.hash ? -1 : a.hash > b.hash ? 1 : 0));
  const payload = {
    accountId,
    amount: String(amount),
    locked: String(locked),
    txs: sortedTxs.map((t) => ({
      amountYocto: String(t.amountYocto),
      blockHeight: t.blockHeight,
      blockTimestampNs: String(t.blockTimestampNs),
      hash: t.hash,
      receiverId: t.receiverId,
      senderId: t.senderId,
      status: t.status,
    })),
  };
  return sha256Hex(canonicalize(payload));
}

// Fetch the account's current state.
// Returns { accountId, amount (yocto string), locked (yocto string),
//           storage_usage, blockHeight }.
// Throws on RPC errors, including a nonexistent account.
export async function getAccount(accountId) {
  if (typeof accountId !== 'string' || accountId.length === 0) {
    throw new Error('getAccount: accountId must be a non-empty string');
  }
  const result = await rpcCall('query', {
    request_type: 'view_account',
    account_id: accountId,
    finality: 'final',
  });
  return {
    accountId,
    amount: String(result.amount),
    locked: String(result.locked),
    storage_usage: Number(result.storage_usage),
    blockHeight: Number(result.block_height),
  };
}

function normalizeTx(result, txHash) {
  const tx = result.transaction;
  const statusObj = result.status ?? {};
  let status;
  if ('SuccessValue' in statusObj || 'SuccessReceiptId' in statusObj) status = 'Success';
  else if ('Failure' in statusObj) status = 'Failure';
  else throw new Error(`verifyTx: unrecognized tx status for ${txHash}: ${JSON.stringify(statusObj)}`);
  // amountYocto counts Transfer actions only. A FunctionCall's attached
  // deposit is not a transfer and counts as "0".
  let amountYocto = 0n;
  for (const action of tx.actions ?? []) {
    if (action && typeof action === 'object' && 'Transfer' in action) {
      amountYocto += BigInt(action.Transfer.deposit);
    }
  }
  return {
    hash: tx.hash,
    senderId: tx.signer_id,
    receiverId: tx.receiver_id,
    amountYocto: amountYocto.toString(),
    status,
    blockHash: result.transaction_outcome?.block_hash,
  };
}

async function blockHeightAndTimestamp(blockHash) {
  if (!blockHash) throw new Error('verifyTx: tx outcome carries no block hash');
  const block = await rpcCall('block', { block_id: blockHash });
  return {
    blockHeight: Number(block.header.height),
    blockTimestampNs: String(block.header.timestamp_nanosec),
  };
}

// Verify one transaction by hash (base58) and sender.
// Returns { hash, senderId, receiverId, amountYocto, status,
//           blockHeight, blockTimestampNs } or null if the tx was never
// observed. Throws on RPC errors and on malformed hashes (caller error).
export async function verifyTx(txHash, senderId) {
  if (typeof txHash !== 'string' || !BASE58_RE.test(txHash)) {
    throw new Error('verifyTx: txHash must be a base58-encoded 256-bit hash (43-44 chars)');
  }
  if (typeof senderId !== 'string' || senderId.length === 0) {
    throw new Error('verifyTx: senderId must be a non-empty string');
  }
  let result = null;
  try {
    result = await rpcCall('tx', [txHash, senderId], { timeoutMs: 60000, retries: 1 });
  } catch (err) {
    if (!isNotObservedError(err)) throw err;
    // Fallback: EXPERIMENTAL_tx_status queries the same store; it is tried
    // once because a tx can be visible to one endpoint and not the other
    // while a node is catching up. A NOT_OBSERVED here means "not found".
    try {
      result = await rpcCall('EXPERIMENTAL_tx_status', [txHash, senderId], { timeoutMs: 60000, retries: 1 });
    } catch (err2) {
      if (isNotObservedError(err2)) return null;
      throw err2;
    }
  }
  const norm = normalizeTx(result, txHash);
  const { blockHeight, blockTimestampNs } = await blockHeightAndTimestamp(norm.blockHash);
  return {
    hash: norm.hash,
    senderId: norm.senderId,
    receiverId: norm.receiverId,
    amountYocto: norm.amountYocto,
    status: norm.status,
    blockHeight,
    blockTimestampNs,
  };
}

// SHA-256 hex of the canonical multi-wallet evidence bundle. Used
// whenever the evidence spans more than one wallet OR any wallet
// carries balanceSamples. Same payload shape as the Node module.
export async function computeMultiDataHash(wallets) {
  if (!Array.isArray(wallets) || wallets.length === 0) {
    throw new Error('computeMultiDataHash: wallets must be a non-empty array');
  }
  const entries = wallets.map((w) => {
    const account = w.account ?? w;
    const txs = w.txs ?? [];
    const samples = Array.isArray(w.balanceSamples) ? w.balanceSamples : [];
    return {
      accountId: account.accountId,
      amount: String(account.amount),
      locked: String(account.locked),
      txs: [...txs]
        .sort((a, b) => (a.hash < b.hash ? -1 : a.hash > b.hash ? 1 : 0))
        .map((t) => ({
          amountYocto: String(t.amountYocto),
          blockHeight: t.blockHeight,
          blockTimestampNs: String(t.blockTimestampNs),
          hash: t.hash,
          receiverId: t.receiverId,
          senderId: t.senderId,
          status: t.status,
        })),
      balanceSamples: [...samples]
        .sort((a, b) => a.blockHeight - b.blockHeight)
        .map((s) => ({ amount: String(s.amount), blockHeight: s.blockHeight })),
    };
  });
  entries.sort((a, b) => (a.accountId < b.accountId ? -1 : a.accountId > b.accountId ? 1 : 0));
  return sha256Hex(canonicalize({ wallets: entries }));
}

// The data hash for a set of snapshots, picking the single- or
// multi-wallet path by the same rule as the Node module.
export async function dataHashForSnapshots(snapshots) {
  if (!Array.isArray(snapshots) || snapshots.length === 0) {
    throw new Error('dataHashForSnapshots: snapshots must be a non-empty array');
  }
  const needsMulti =
    snapshots.length > 1 || snapshots.some((s) => Array.isArray(s.balanceSamples) && s.balanceSamples.length > 0);
  if (!needsMulti) {
    const s = snapshots[0];
    return computeDataHash(s.account.accountId, s.account.amount, s.account.locked, s.txs);
  }
  return computeMultiDataHash(snapshots);
}

// Pure helper: the block heights a balance sample covers, newest
// last. Exported so callers sampling SEVERAL wallets compute the
// heights ONCE and pass the same list to each — the sustained and
// time-weighted claims require every wallet's samples to sit on the
// same heights, and two sequential "current height" reads would drift
// apart by a block or two.
export function computeSampleHeights(currentBlockHeight, { windowHours, samples }) {
  if (!Number.isInteger(currentBlockHeight) || currentBlockHeight < 0) {
    throw new Error('computeSampleHeights: currentBlockHeight must be a non-negative integer');
  }
  if (typeof windowHours !== 'number' || !(windowHours > 0)) {
    throw new Error('computeSampleHeights: windowHours must be a positive number');
  }
  if (!Number.isInteger(samples) || samples < 2) {
    throw new Error('computeSampleHeights: samples must be an integer >= 2');
  }
  const step = Math.max(1, Math.floor((windowHours * 3600) / samples));
  const heights = [];
  for (let i = samples - 1; i >= 0; i -= 1) {
    const height = currentBlockHeight - i * step;
    if (height < 0) throw new Error('computeSampleHeights: sampled height is negative — window too long for this chain');
    heights.push(height);
  }
  return heights;
}

// Sample an account's balance history at past block heights.
// Same rules as the Node module: ~1 block per second, `samples`
// readings ending at the current height, spaced evenly across the
// window. A height the node cannot serve is recorded in
// missingHeights, not thrown (see sampleBalanceHistoryDetailed);
// only a run with zero successful readings throws. Each sample also
// carries blockTimestampNs when the block header was served.
// Pass explicit `heights` (from computeSampleHeights, computed once)
// when sampling several wallets: their samples must sit on the same
// heights or the sustained/time-weighted claims refuse to run.
export async function sampleBalanceHistoryDetailed(accountId, { windowHours, samples, heights }) {
  if (typeof accountId !== 'string' || accountId.length === 0) {
    throw new Error('sampleBalanceHistory: accountId must be a non-empty string');
  }
  if (typeof windowHours !== 'number' || !(windowHours > 0)) {
    throw new Error('sampleBalanceHistory: windowHours must be a positive number');
  }
  if (!Number.isInteger(samples) || samples < 2) {
    throw new Error('sampleBalanceHistory: samples must be an integer >= 2');
  }
  let sampleHeights;
  if (heights !== undefined) {
    if (!Array.isArray(heights) || heights.length < 2 || heights.length !== samples
      || heights.some((h) => !Number.isInteger(h) || h < 0)) {
      throw new Error('sampleBalanceHistory: heights must be an array of samples non-negative integers');
    }
    sampleHeights = heights;
  } else {
    const current = await getAccount(accountId);
    sampleHeights = computeSampleHeights(current.blockHeight, { windowHours, samples });
  }
  const out = [];
  const missingHeights = [];
  for (const height of sampleHeights) {
    let result;
    try {
      result = await rpcCall('query', {
        request_type: 'view_account',
        account_id: accountId,
        block_id: height,
      });
    } catch {
      missingHeights.push(height);
      continue;
    }
    const sample = { blockHeight: height, amount: String(result.amount) };
    try {
      const block = await rpcCall('block', { block_id: height });
      sample.blockTimestampNs = String(block.header.timestamp_nanosec);
    } catch {
      // Header unavailable: the balance reading stands, and
      // describeSampling estimates this timestamp instead.
    }
    out.push(sample);
  }
  if (out.length === 0) {
    throw new Error(
      'sampleBalanceHistory: no balance samples could be read '
      + `(account ${accountId}, ${samples} requested heights, all unservable) — try a shorter window`,
    );
  }
  return { samples: out, missingHeights, requestedHeights: sampleHeights, samplesRequested: samples };
}

export async function sampleBalanceHistory(accountId, { windowHours, samples, heights }) {
  const detailed = await sampleBalanceHistoryDetailed(accountId, { windowHours, samples, heights });
  return detailed.samples;
}

// Fetch a full snapshot for a claim: current account state plus the
// verified transactions the prover supplied.
// txHashes entries may be plain base58 hashes (sender assumed to be the
// account) or { hash, senderId } objects (needed for incoming transfers,
// whose sender is someone else). Unknown or unobserved hashes are skipped;
// duplicates are collapsed. Returned txs are sorted by hash, so the
// snapshot (and its dataHash) is canonical.
// opts.balanceSamples: { windowHours, samples } — when given, the
// snapshot also carries balanceSamples, balanceSampleWindowHours and
// a `sampling` record (see describeSampling), and the dataHash is
// computed by the multi-wallet path.
export async function fetchAccountSnapshot(accountId, txHashes = [], opts = {}) {
  const account = await getAccount(accountId);
  const seen = new Set();
  const txs = [];
  for (const entry of txHashes) {
    const hash = typeof entry === 'string' ? entry : entry?.hash;
    const senderId = typeof entry === 'string' ? accountId : entry?.senderId ?? accountId;
    if (typeof hash !== 'string' || seen.has(hash)) continue;
    seen.add(hash);
    const verified = await verifyTx(hash, senderId);
    if (verified) txs.push(verified);
  }
  txs.sort((a, b) => (a.hash < b.hash ? -1 : a.hash > b.hash ? 1 : 0));
  const snapshot = { account, txs, blockHeight: account.blockHeight };
  if (opts.balanceSamples) {
    const detailed = await sampleBalanceHistoryDetailed(accountId, opts.balanceSamples);
    snapshot.balanceSamples = detailed.samples;
    snapshot.balanceSampleWindowHours = opts.balanceSamples.windowHours;
    snapshot.sampling = describeSampling(snapshot, {
      samplesRequested: detailed.samplesRequested,
      requestedHeights: detailed.requestedHeights,
      missingHeights: detailed.missingHeights,
    });
  }
  snapshot.dataHash = await dataHashForSnapshots([snapshot]);
  return snapshot;
}

// NEAR Blocks indexer (v3 API) base for testnet. Used only to discover
// the account's recent transaction hashes, so the user never has to
// paste them. The hashes are still verified one by one against the
// NEAR RPC (verifyTx), so the indexer is a discovery aid, not a trust
// source: a hash it returns that the RPC cannot verify is skipped.
export const NEARBLOCKS_TESTNET_API = 'https://api-testnet.nearblocks.io/v3';

// Fetch the account's most recent transactions from the NEAR Blocks
// indexer and return them as { hash, senderId } entries, newest first.
// Returns [] on any indexer error, so the caller falls back to the
// manually pasted hashes. Limit is capped at 25.
export async function fetchRecentTxHashes(accountId, limit = 25) {
  const n = Math.max(1, Math.min(25, Math.floor(limit) || 25));
  const url = `${NEARBLOCKS_TESTNET_API}/accounts/${encodeURIComponent(accountId)}/txns?limit=${n}`;
  try {
    const res = await fetch(url, { headers: { Accept: 'application/json' } });
    if (!res.ok) return [];
    const json = await res.json();
    const data = Array.isArray(json?.data) ? json.data : [];
    const out = [];
    for (const t of data) {
      const hash = t?.transaction_hash;
      const senderId = t?.signer_account_id;
      if (typeof hash === 'string' && hash.length >= 43 && typeof senderId === 'string' && senderId) {
        out.push({ hash, senderId });
      }
    }
    return out;
  } catch (_) {
    return [];
  }
}
