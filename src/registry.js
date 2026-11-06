// VeilProof registry v2 client helpers (node side).
//
// The v2 contract (contract/src/lib.rs, CONTRACT_VERSION 2.0.0)
// separates identities: the treasury never appears onchain, the
// publisher is an allowlisted dedicated account, and the controller is
// named only as a salted commitment. These helpers compute those
// commitments and probe which contract version a registry runs, so
// callers keep working against the deployed v1 registry until the
// migration in docs/contract-migration.md runs.
//
// Commitment formula (MUST match the contract's commitment_hex and the
// browser mirror in public/js/registry.js byte for byte):
//   sha256_hex("<domain>:<salt>:<account_id>")
// Domains: "veilproof-publisher-v1", "veilproof-controller-v1".
// Salt: fresh random 64-hex per claim (newCommitmentSalt).
import { createHash, randomBytes } from 'node:crypto';

export const PUBLISHER_COMMITMENT_DOMAIN = 'veilproof-publisher-v1';
export const CONTROLLER_COMMITMENT_DOMAIN = 'veilproof-controller-v1';

function assertHex64(value, name) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) {
    throw new Error(`registry: ${name} must be exactly 64 lowercase hex characters`);
  }
}

/// sha256_hex(`${domain}:${salt}:${accountId}`), UTF-8.
export function commitmentHex(domain, salt, accountId) {
  if (typeof domain !== 'string' || domain.length === 0) {
    throw new Error('registry: domain must be a non-empty string');
  }
  assertHex64(salt, 'salt');
  if (typeof accountId !== 'string' || accountId.length === 0) {
    throw new Error('registry: accountId must be a non-empty string');
  }
  return createHash('sha256').update(`${domain}:${salt}:${accountId}`, 'utf8').digest('hex');
}

/// Fresh random salt for one claim's commitments (32 random bytes,
/// rendered as 64 lowercase hex — the contract requires 64-hex salts).
export function newCommitmentSalt() {
  return randomBytes(32).toString('hex');
}

/// Both commitments for one publish, plus the salt. The publisher
/// commitment is computed for the account that will SIGN the publish
/// (the contract recomputes it from the real signer and rejects a
/// mismatch); the controller commitment is computed for the account
/// authorised to revoke (which never sends its id to the contract).
export function buildPublishCommitments({ publisherAccountId, controllerAccountId, salt = newCommitmentSalt() }) {
  assertHex64(salt, 'salt');
  return {
    commitment_salt: salt,
    publisher_commitment: commitmentHex(PUBLISHER_COMMITMENT_DOMAIN, salt, publisherAccountId),
    controller_commitment: commitmentHex(CONTROLLER_COMMITMENT_DOMAIN, salt, controllerAccountId),
  };
}

/// True for a v2 version string ("2.0.0", "2.x", ...).
export function isV2Version(version) {
  return typeof version === 'string' && version.startsWith('2.');
}

/// Probe a registry's version. `viewFunction` is the caller's
/// (methodName, args) => result view helper. Returns the version
/// string, or null when the registry has no get_version method — i.e.
/// it is the deployed v1 contract. A missing method is a version
/// signal, not an error, so any throw maps to null; a registry that
/// answers get_version with a non-string is also treated as unknown.
export async function probeContractVersion(viewFunction) {
  try {
    const version = await viewFunction('get_version', {});
    return typeof version === 'string' ? version : null;
  } catch {
    return null;
  }
}

/// The extra publish_claim args a v2 registry requires, for one publish.
/// Returns { args, commitments } where args is the full argument object
/// (hashes + expiry + commitments) and commitments carries the salt and
/// both commitments for post-publish verification.
export function buildV2PublishArgs({
  claimId,
  reportHash,
  evidenceHash,
  policyHash,
  expiresAt,
  publisherAccountId,
  controllerAccountId,
  salt,
}) {
  const commitments = buildPublishCommitments({ publisherAccountId, controllerAccountId, salt });
  return {
    args: {
      claim_id: claimId,
      report_hash: reportHash,
      evidence_hash: evidenceHash,
      policy_hash: policyHash,
      expires_at: expiresAt,
      controller_commitment: commitments.controller_commitment,
      publisher_commitment: commitments.publisher_commitment,
      commitment_salt: commitments.commitment_salt,
    },
    commitments,
  };
}
