// VeilProof onchain ingestion — NEAR testnet RPC reads only.
// No keys, no signing, no secrets. The chain is the source of truth:
// a verifier can re-fetch everything here and reproduce the same facts.
//
// Live RPC behaviour, verified 2026-11-06 against rpc.testnet.near.org:
// - `tx` expects the hash as BASE58 (hex is rejected with a parse error).
// - A well-formed but absent tx does NOT return a clean "not found".
//   It returns HANDLER_ERROR / TIMEOUT_ERROR with cause NOT_OBSERVED,
//   or HTTP 408 (the node waits for the tx to appear, then times out).
//   verifyTx maps exactly those errors to null, and throws on every
//   other RPC error.
// - Neither `tx` nor `EXPERIMENTAL_tx_status` returns block height or
//   timestamp; verifyTx fetches the block by transaction_outcome.block_hash
//   to get both.
// - Regular nodes prune old transactions (a few epochs). A tx that existed
//   long ago may come back NOT_OBSERVED. Claims must use recent txs.
import { createHash } from 'node:crypto';

export const NEAR_TESTNET_RPC = 'https://rpc.testnet.near.org';

const BASE58_RE = /^[1-9A-HJ-NP-Za-km-z]{43,44}$/;

class RpcError extends Error {
  constructor(message, rpcError) {
    super(message);
    this.name = 'RpcError';
    this.rpcError = rpcError;
  }
}

// One JSON-RPC call. Retries ONCE on network errors only (fetch throwing,
// HTTP failure, local timeout). RPC-level errors are thrown immediately.
async function rpcCall(method, params, { timeoutMs = 30000, retries = 1 } = {}) {
  let lastError;
  for (let attempt = 0; attempt <= retries; attempt += 1) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(NEAR_TESTNET_RPC, {
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
      throw new Error(`NEAR RPC ${method} network error: ${err.message}`);
    }
  }
  throw lastError;
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
export function computeDataHash(accountId, amount, locked, txs) {
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
  return createHash('sha256').update(canonicalize(payload)).digest('hex');
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
// carries balanceSamples (sustained/time-weighted evidence). The
// payload is the per-wallet data sorted by accountId, each wallet
// carrying its account state, verified txs (sorted by hash) and its
// recorded balance samples (sorted by height, empty when absent).
// The single-wallet, no-samples case keeps using computeDataHash, so
// reports published before samples existed verify exactly as before.
// Both the prover and the verifier pick the path by the same rule —
// multi when wallets.length > 1 or any wallet has balanceSamples —
// so they always compute the same hash for the same disclosure.
export function computeMultiDataHash(wallets) {
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
  return createHash('sha256').update(canonicalize({ wallets: entries })).digest('hex');
}

// The data hash for a set of snapshots, picking the single- or
// multi-wallet path by the rule above. Snapshots are plain objects
// shaped like fetchAccountSnapshot's return ({ account, txs,
// balanceSamples? }).
export function dataHashForSnapshots(snapshots) {
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

// Sample an account's balance history at past block heights.
// NEAR makes ~1 block per second, so a window of W hours spans about
// W*3600 blocks. `samples` readings are taken ending at the current
// height, spaced evenly across the window (oldest first). Each reading
// is a view_account query at that height, so the values are genuine
// chain state a verifier can re-fetch at the same heights.
// Throws when the account did not exist at a sampled height (the
// account is younger than the window) or the node cannot serve that
// height — the caller should offer a shorter window then.
export async function sampleBalanceHistory(accountId, { windowHours, samples }) {
  if (typeof accountId !== 'string' || accountId.length === 0) {
    throw new Error('sampleBalanceHistory: accountId must be a non-empty string');
  }
  if (typeof windowHours !== 'number' || !(windowHours > 0)) {
    throw new Error('sampleBalanceHistory: windowHours must be a positive number');
  }
  if (!Number.isInteger(samples) || samples < 2) {
    throw new Error('sampleBalanceHistory: samples must be an integer >= 2');
  }
  const current = await getAccount(accountId);
  const step = Math.max(1, Math.floor((windowHours * 3600) / samples));
  const heights = [];
  for (let i = samples - 1; i >= 0; i -= 1) {
    heights.push(current.blockHeight - i * step);
  }
  const out = [];
  for (const height of heights) {
    if (height < 0) throw new Error('sampleBalanceHistory: sampled height is negative — window too long for this chain');
    const result = await rpcCall('query', {
      request_type: 'view_account',
      account_id: accountId,
      block_id: height,
    });
    out.push({ blockHeight: height, amount: String(result.amount) });
  }
  return out;
}

// Fetch a full snapshot for a claim: current account state plus the
// verified transactions the prover supplied.
// txHashes entries may be plain base58 hashes (sender assumed to be the
// account) or { hash, senderId } objects (needed for incoming transfers,
// whose sender is someone else). Unknown or unobserved hashes are skipped;
// duplicates are collapsed. Returned txs are sorted by hash, so the
// snapshot (and its dataHash) is canonical.
// opts.balanceSamples: { windowHours, samples } — when given, the
// snapshot also carries balanceSamples (see sampleBalanceHistory) and
// balanceSampleWindowHours, and the dataHash is computed by the
// multi-wallet path (which covers samples) instead of computeDataHash.
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
    snapshot.balanceSamples = await sampleBalanceHistory(accountId, opts.balanceSamples);
    snapshot.balanceSampleWindowHours = opts.balanceSamples.windowHours;
  }
  snapshot.dataHash = dataHashForSnapshots([snapshot]);
  return snapshot;
}
