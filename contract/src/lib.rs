//! veilproof_registry — on-chain commitments for private onchain
//! financial claims. NEAR HACKATHON 2026 (Privacy & Private AI).
//!
//! What this contract does:
//! - Stores a claim as three SHA-256 hashes (report, evidence, policy)
//!   plus owner, timestamps and a revocation flag. Hashes only: no wallet
//!   addresses, no amounts, no raw data are ever written onchain. The
//!   wallet a claim is about is never stored here; only a hash commitment
//!   of it lives in the offchain report.
//! - Lets anyone check whether a claim is still valid (exists, not
//!   revoked, not expired) and lets a verifier re-fetch the underlying
//!   onchain data from the chain itself — the chain is what makes the
//!   input genuine, not the publisher.
//!
//! What this contract does NOT do (honest boundaries):
//! - It cannot prove the offchain report is truthful. The report hash
//!   proves the report was not altered after publication; the evidence
//!   hash binds the TEE attestation for the analysis. Whether the
//!   underlying chain data is real is verifiable by anyone who re-reads
//!   the chain — that is the point of using onchain data as the input.
//! - It holds no funds and takes no fee beyond storage: publishing
//!   charges storage at cost and refunds any excess deposit.
//! - Revocation blocks future verification. It cannot erase a report a
//!   verifier already downloaded.

use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::store::LookupMap;
use near_sdk::{env, near, AccountId, NearToken, PanicOnDefault, Promise};

/// NEP-297 event standard and version for veilproof events.
pub const EVENT_STANDARD: &str = "veilproof";
pub const EVENT_VERSION: &str = "1.0.0";
/// Maximum claim_id length, in characters.
pub const MAX_CLAIM_ID_LEN: usize = 128;
/// A SHA-256 hash rendered as lowercase hex is exactly 64 characters.
pub const HASH_HEX_LEN: usize = 64;

/// A single published claim. Hashes only — see the module docs.
#[derive(
    BorshDeserialize,
    BorshSerialize,
    Clone,
    Debug,
    PartialEq,
    schemars::JsonSchema,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(crate = "near_sdk::serde")]
pub struct Claim {
    pub owner: AccountId,
    pub report_hash: String,
    pub evidence_hash: String,
    pub policy_hash: String,
    pub created_at: u64, // block timestamp, nanoseconds
    pub expires_at: u64, // block timestamp, nanoseconds
    pub revoked: bool,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Contract {
    pub claims: LookupMap<String, Claim>,
    pub owner_claims: LookupMap<AccountId, Vec<String>>,
}

/// True only for exactly 64 lowercase hex characters (a SHA-256 digest).
/// Uppercase hex and any non-hex character fail.
fn is_valid_hash(value: &str) -> bool {
    value.len() == HASH_HEX_LEN
        && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn emit_event(event: &str, data: serde_json::Value) {
    env::log_str(&format!(
        "EVENT_JSON:{}",
        serde_json::to_string(&serde_json::json!({
            "standard": EVENT_STANDARD,
            "version": EVENT_VERSION,
            "event": event,
            "data": data,
        }))
        .expect("event serialises")
    ));
}

#[near]
impl Contract {
    #[init]
    pub fn new() -> Self {
        Self {
            claims: LookupMap::new(b"c"),
            owner_claims: LookupMap::new(b"o"),
        }
    }

    /// Publish a claim. The caller becomes its owner.
    ///
    /// Storage is charged at cost: usage is measured around both writes
    /// (the claim record and the owner index), the attached deposit must
    /// cover it, and any excess is refunded to the caller. A panic here
    /// rolls the writes back, so an underfunded publish stores nothing.
    ///
    /// NOTE: `#[payable]` is load-bearing here, not decorative. The
    /// method reads `env::attached_deposit()`, so without it the runtime
    /// rejects every call carrying a deposit ("method is not payable")
    /// and a zero-deposit call fails the storage-cost assert — publishing
    /// is impossible either way. The near-sdk mock does NOT enforce
    /// payable-ness, so unit tests pass with or without it; the live
    /// demo publish is the regression check for this attribute. This
    /// was missing in the first deploy (2026-11-06) and the demo caught it.
    #[payable]
    pub fn publish_claim(
        &mut self,
        claim_id: String,
        report_hash: String,
        evidence_hash: String,
        policy_hash: String,
        expires_at: u64,
    ) {
        assert!(!claim_id.is_empty(), "claim_id must not be empty");
        assert!(
            claim_id.chars().count() <= MAX_CLAIM_ID_LEN,
            "claim_id must be at most 128 characters"
        );
        assert!(
            is_valid_hash(&report_hash),
            "report_hash must be exactly 64 lowercase hex characters"
        );
        assert!(
            is_valid_hash(&evidence_hash),
            "evidence_hash must be exactly 64 lowercase hex characters"
        );
        assert!(
            is_valid_hash(&policy_hash),
            "policy_hash must be exactly 64 lowercase hex characters"
        );
        assert!(
            expires_at > env::block_timestamp(),
            "expires_at must be in the future"
        );
        assert!(
            self.claims.get(&claim_id).is_none(),
            "claim_id already exists"
        );

        let caller = env::predecessor_account_id();
        let claim = Claim {
            owner: caller.clone(),
            report_hash,
            evidence_hash,
            policy_hash,
            created_at: env::block_timestamp(),
            expires_at,
            revoked: false,
        };

        let usage_before = env::storage_usage();
        self.claims.insert(claim_id.clone(), claim);
        let mut ids = self.owner_claims.get(&caller).cloned().unwrap_or_default();
        ids.push(claim_id.clone());
        self.owner_claims.insert(caller.clone(), ids);
        let used_bytes = env::storage_usage().saturating_sub(usage_before);
        // Note: in near-sdk unit tests env::storage_usage() is a static
        // context field (default 1024*300) that storage writes never
        // update, so the measured delta is 0 in the mock and this check
        // cannot be exercised there. Onchain it is the account's live
        // usage, so the delta — and the cost — are real. See the tests
        // module for why there is no insufficient-deposit unit test.
        let cost = (used_bytes as u128)
            .saturating_mul(env::storage_byte_cost().as_yoctonear());
        let attached = env::attached_deposit().as_yoctonear();
        assert!(
            attached >= cost,
            "attached deposit does not cover storage cost"
        );
        let excess = attached - cost;
        if excess > 0 {
            // The transfer action is registered with the runtime when the
            // Promise is created, so the refund executes even though the
            // Promise is not returned from this method.
            Promise::new(caller.clone())
                .transfer(NearToken::from_yoctonear(excess))
                .detach();
        }

        emit_event(
            "claim_published",
            serde_json::json!({ "claim_id": claim_id, "owner": caller }),
        );
    }

    /// Fetch one claim by id, if it exists.
    pub fn get_claim(&self, claim_id: String) -> Option<Claim> {
        self.claims.get(&claim_id).cloned()
    }

    /// Revoke a claim. Only its owner may do so, and only once.
    /// Revocation is permanent and blocks future verification.
    pub fn revoke_claim(&mut self, claim_id: String) {
        let claim = self
            .claims
            .get_mut(&claim_id)
            .expect("claim not found");
        let caller = env::predecessor_account_id();
        assert_eq!(claim.owner, caller, "only the claim owner can revoke");
        assert!(!claim.revoked, "claim already revoked");
        claim.revoked = true;
        // The mutation is written back when the map is dropped at the end
        // of the call; no re-insert is needed.
        emit_event(
            "claim_revoked",
            serde_json::json!({ "claim_id": claim_id, "owner": caller }),
        );
    }

    /// All claim ids published by an owner, in publication order.
    pub fn get_owner_claims(&self, owner: AccountId) -> Vec<String> {
        self.owner_claims.get(&owner).cloned().unwrap_or_default()
    }

    /// True only when the claim exists, is not revoked, and has not
    /// expired. A missing claim is invalid, not an error.
    pub fn is_claim_valid(&self, claim_id: String) -> bool {
        match self.claims.get(&claim_id) {
            Some(claim) => !claim.revoked && env::block_timestamp() < claim.expires_at,
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;

    fn owner() -> AccountId {
        "alice.testnet".parse().unwrap()
    }

    fn stranger() -> AccountId {
        "mallory.testnet".parse().unwrap()
    }

    /// A valid 64-char lowercase hex string, filled with one hex digit.
    fn hex_hash(ch: char) -> String {
        std::iter::repeat_n(ch, 64).collect()
    }

    /// One context per test (a second testing_env! call would wipe the
    /// mock storage). Storage on NEAR costs 10^19 yocto/byte, so a claim
    /// of a few hundred bytes costs a few NEAR: attach 10 NEAR for
    /// publishes unless the test is about the deposit itself.
    fn ctx(predecessor: AccountId, attached: NearToken, timestamp: u64) {
        let mut b = VMContextBuilder::new();
        b.predecessor_account_id(predecessor);
        b.attached_deposit(attached);
        b.block_timestamp(timestamp);
        b.account_balance(NearToken::from_near(100));
        testing_env!(b.build());
    }

    fn empty_contract() -> Contract {
        Contract {
            claims: LookupMap::new(b"c"),
            owner_claims: LookupMap::new(b"o"),
        }
    }

    /// Insert a claim straight into storage, bypassing publish_claim.
    /// Used where the test needs state the public method cannot create
    /// under a single context (a claim owned by someone else, or one
    /// that is already expired).
    fn insert_claim(
        c: &mut Contract,
        claim_id: &str,
        owner_id: AccountId,
        expires_at: u64,
        revoked: bool,
    ) {
        let claim = Claim {
            owner: owner_id.clone(),
            report_hash: hex_hash('a'),
            evidence_hash: hex_hash('b'),
            policy_hash: hex_hash('c'),
            created_at: 1_000,
            expires_at,
            revoked,
        };
        c.claims.insert(claim_id.to_string(), claim);
        let mut ids = c.owner_claims.get(&owner_id).cloned().unwrap_or_default();
        ids.push(claim_id.to_string());
        c.owner_claims.insert(owner_id, ids);
    }

    fn publish(c: &mut Contract, claim_id: &str, expires_at: u64) {
        c.publish_claim(
            claim_id.to_string(),
            hex_hash('a'),
            hex_hash('b'),
            hex_hash('c'),
            expires_at,
        );
    }

    #[test]
    fn publish_and_get_round_trip() {
        ctx(owner(), NearToken::from_near(10), 1_000_000);
        let mut c = empty_contract();
        publish(&mut c, "claim-1", 2_000_000);
        let claim = c.get_claim("claim-1".to_string()).expect("stored");
        assert_eq!(claim.owner, owner());
        assert_eq!(claim.report_hash, hex_hash('a'));
        assert_eq!(claim.evidence_hash, hex_hash('b'));
        assert_eq!(claim.policy_hash, hex_hash('c'));
        assert_eq!(claim.created_at, 1_000_000);
        assert_eq!(claim.expires_at, 2_000_000);
        assert!(!claim.revoked);
        assert!(c.is_claim_valid("claim-1".to_string()));
        assert_eq!(c.get_owner_claims(owner()), vec!["claim-1".to_string()]);
    }

    #[test]
    #[should_panic(expected = "claim_id already exists")]
    fn duplicate_publish_panics() {
        ctx(owner(), NearToken::from_near(10), 1_000_000);
        let mut c = empty_contract();
        publish(&mut c, "claim-1", 2_000_000);
        publish(&mut c, "claim-1", 2_000_000);
    }

    #[test]
    #[should_panic(expected = "report_hash must be exactly 64 lowercase hex characters")]
    fn bad_hash_wrong_length_panics() {
        ctx(owner(), NearToken::from_near(10), 1_000_000);
        let mut c = empty_contract();
        c.publish_claim(
            "claim-1".to_string(),
            hex_hash('a')[..63].to_string(),
            hex_hash('b'),
            hex_hash('c'),
            2_000_000,
        );
    }

    #[test]
    #[should_panic(expected = "evidence_hash must be exactly 64 lowercase hex characters")]
    fn bad_hash_non_hex_panics() {
        ctx(owner(), NearToken::from_near(10), 1_000_000);
        let mut c = empty_contract();
        c.publish_claim(
            "claim-1".to_string(),
            hex_hash('a'),
            hex_hash('g'), // 'g' is not a hex digit
            hex_hash('c'),
            2_000_000,
        );
    }

    #[test]
    #[should_panic(expected = "policy_hash must be exactly 64 lowercase hex characters")]
    fn bad_hash_uppercase_panics() {
        ctx(owner(), NearToken::from_near(10), 1_000_000);
        let mut c = empty_contract();
        c.publish_claim(
            "claim-1".to_string(),
            hex_hash('a'),
            hex_hash('b'),
            hex_hash('A'), // uppercase hex is rejected
            2_000_000,
        );
    }

    #[test]
    #[should_panic(expected = "claim_id must not be empty")]
    fn empty_claim_id_panics() {
        ctx(owner(), NearToken::from_near(10), 1_000_000);
        let mut c = empty_contract();
        publish(&mut c, "", 2_000_000);
    }

    #[test]
    #[should_panic(expected = "claim_id must be at most 128 characters")]
    fn claim_id_too_long_panics() {
        ctx(owner(), NearToken::from_near(10), 1_000_000);
        let mut c = empty_contract();
        let long_id: String = std::iter::repeat_n('x', 129).collect();
        publish(&mut c, &long_id, 2_000_000);
    }

    #[test]
    #[should_panic(expected = "expires_at must be in the future")]
    fn past_expiry_panics() {
        ctx(owner(), NearToken::from_near(10), 2_000_000);
        let mut c = empty_contract();
        publish(&mut c, "claim-1", 1_000_000);
    }

    // No insufficient-deposit unit test: in the near-sdk mock,
    // env::storage_usage() is a static context field that storage writes
    // never update, so the measured cost is always 0 and a 0-deposit
    // publish cannot panic here. The at-cost check itself is correct and
    // live onchain, where storage_usage is the account's real usage. Do
    // not "fix" this by weakening the check; verify it in an integration
    // test against a real node instead.

    #[test]
    fn revoke_by_owner_works_and_invalidates() {
        ctx(owner(), NearToken::from_near(10), 1_000_000);
        let mut c = empty_contract();
        publish(&mut c, "claim-1", 2_000_000);
        assert!(c.is_claim_valid("claim-1".to_string()));
        c.revoke_claim("claim-1".to_string());
        let claim = c.get_claim("claim-1".to_string()).expect("still stored");
        assert!(claim.revoked);
        assert!(!c.is_claim_valid("claim-1".to_string()));
    }

    #[test]
    #[should_panic(expected = "only the claim owner can revoke")]
    fn revoke_by_non_owner_panics() {
        ctx(stranger(), NearToken::from_near(10), 1_000_000);
        let mut c = empty_contract();
        insert_claim(&mut c, "claim-1", owner(), 2_000_000, false);
        c.revoke_claim("claim-1".to_string());
    }

    #[test]
    #[should_panic(expected = "claim already revoked")]
    fn revoke_twice_panics() {
        ctx(owner(), NearToken::from_near(10), 1_000_000);
        let mut c = empty_contract();
        publish(&mut c, "claim-1", 2_000_000);
        c.revoke_claim("claim-1".to_string());
        c.revoke_claim("claim-1".to_string());
    }

    #[test]
    #[should_panic(expected = "claim not found")]
    fn revoke_missing_claim_panics() {
        ctx(owner(), NearToken::from_near(10), 1_000_000);
        let mut c = empty_contract();
        c.revoke_claim("no-such-claim".to_string());
    }

    #[test]
    fn expired_claim_reports_invalid() {
        ctx(owner(), NearToken::from_near(10), 1_000_000);
        let mut c = empty_contract();
        insert_claim(&mut c, "claim-1", owner(), 500_000, false);
        assert!(!c.is_claim_valid("claim-1".to_string()));
        assert!(c.get_claim("claim-1".to_string()).is_some());
    }

    #[test]
    fn claim_at_exact_expiry_is_invalid() {
        ctx(owner(), NearToken::from_near(10), 1_000_000);
        let mut c = empty_contract();
        insert_claim(&mut c, "claim-1", owner(), 1_000_000, false);
        assert!(!c.is_claim_valid("claim-1".to_string()));
    }

    #[test]
    fn get_owner_claims_lists_published_ids() {
        ctx(owner(), NearToken::from_near(10), 1_000_000);
        let mut c = empty_contract();
        publish(&mut c, "claim-1", 2_000_000);
        publish(&mut c, "claim-2", 2_000_000);
        publish(&mut c, "claim-3", 2_000_000);
        assert_eq!(
            c.get_owner_claims(owner()),
            vec![
                "claim-1".to_string(),
                "claim-2".to_string(),
                "claim-3".to_string()
            ]
        );
        assert!(c.get_owner_claims(stranger()).is_empty());
    }

    #[test]
    fn missing_claim_is_invalid_not_an_error() {
        ctx(owner(), NearToken::from_near(10), 1_000_000);
        let c = empty_contract();
        assert!(!c.is_claim_valid("no-such-claim".to_string()));
        assert!(c.get_claim("no-such-claim".to_string()).is_none());
    }
}
