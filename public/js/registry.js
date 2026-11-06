// VeilProof registry v2 client helpers (browser side).
//
// Mirror of src/registry.js (node). The commitment formula MUST match
// the contract's commitment_hex byte for byte:
//   sha256_hex("<domain>:<salt>:<account_id>")
// Domains: "veilproof-publisher-v1", "veilproof-controller-v1".
// Salt: fresh random 64-hex per claim.
//
// Difference from the node mirror: Web Crypto is async, so
// commitmentHex returns a Promise. randomHex comes from ./crypto.js.
import { sha256Hex, randomHex } from './crypto.js';

export const PUBLISHER_COMMITMENT_DOMAIN = 'veilproof-publisher-v1';
export const CONTROLLER_COMMITMENT_DOMAIN = 'veilproof-controller-v1';

function assertHex64(value, name) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) {
    throw new Error('registry: ' + name + ' must be exactly 64 lowercase hex characters');
  }
}

/// sha256_hex(`${domain}:${salt}:${accountId}`), UTF-8.
export async function commitmentHex(domain, salt, accountId) {
  if (typeof domain !== 'string' || domain.length === 0) {
    throw new Error('registry: domain must be a non-empty string');
  }
  assertHex64(salt, 'salt');
  if (typeof accountId !== 'string' || accountId.length === 0) {
    throw new Error('registry: accountId must be a non-empty string');
  }
  return sha256Hex(domain + ':' + salt + ':' + accountId);
}

/// Fresh random salt for one claim's commitments (32 random bytes,
/// rendered as 64 lowercase hex — the contract requires 64-hex salts).
export function newCommitmentSalt() {
  return randomHex(32);
}

/// Both commitments for one publish, plus the salt. The publisher
/// commitment is computed for the account that will SIGN the publish
/// (the contract recomputes it from the real signer and rejects a
/// mismatch); the controller commitment is computed for the account
/// authorised to revoke (which never sends its id to the contract).
export async function buildPublishCommitments({ publisherAccountId, controllerAccountId, salt = newCommitmentSalt() }) {
  assertHex64(salt, 'salt');
  return {
    commitment_salt: salt,
    publisher_commitment: await commitmentHex(PUBLISHER_COMMITMENT_DOMAIN, salt, publisherAccountId),
    controller_commitment: await commitmentHex(CONTROLLER_COMMITMENT_DOMAIN, salt, controllerAccountId),
  };
}

/// True for a v2 version string ("2.0.0", "2.x", ...).
export function isV2Version(version) {
  return typeof version === 'string' && version.startsWith('2.');
}

/// Probe a registry's version. `rpcView` is the caller's
/// (methodName, args) => result view helper. Returns the version
/// string, or null when the registry has no get_version method — i.e.
/// it is the deployed v1 contract.
export async function probeContractVersion(rpcView) {
  try {
    const version = await rpcView('get_version', {});
    return typeof version === 'string' ? version : null;
  } catch (err) {
    return null;
  }
}
