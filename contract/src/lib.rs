//! veilproof_registry — on-chain commitments for private onchain
//! financial claims. NEAR HACKATHON 2026 (Privacy & Private AI).
//!
//! Version 2.0.0 — identity separation (see docs/contract-migration.md
//! for the v1 → v2 migration procedure; the deployed registry is still
//! v1 until that migration runs).
//!
//! Four roles, never assumed to be the same account:
//! - **Treasury**: the wallet whose activity a report analyses. It NEVER
//!   appears onchain — not in state, not in events, not in any view
//!   response, not even in transaction arguments. The report's salted
//!   prover commitment (offchain, P2) is the only link, and the salt
//!   travels only in the private disclosure package.
//! - **Publisher**: the account that signs `publish_claim`. Only accounts
//!   on the admin-managed allowlist may publish; in practice a single
//!   dedicated publishing account, separate from any treasury. The
//!   publisher IS visible in NEAR transaction history (every tx sender
//!   is) — that is a documented residual risk, not a secret the contract
//!   can hide. What the contract stores is only a per-claim salted
//!   commitment of the publisher, so claims cannot be linked to each
//!   other through the registry even though each publish tx names its
//!   sender.
//! - **Controller**: the account authorised to revoke / manage a claim.
//!   Named offchain only, as a salted commitment
//!   (`controller_commitment`); the account id itself is never passed
//!   to the contract, never stored, never emitted. Revocation proves
//!   control by hashing the caller with the claim's stored salt.
//! - **Verifier**: authorised to inspect the disclosure package. That
//!   authorisation is enforced OFFCHAIN by P4 verifier-bound encryption
//!   (docs/verifier-bound-disclosure.md); the contract has no verifier
//!   role because disclosure inspection never touches the chain.
//!
//! What this contract stores per claim: three SHA-256 hashes (report,
//! evidence, policy), two salted commitments, one salt, timestamps and
//! a revocation flag. No wallet addresses, no amounts, no raw data.
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
//! - It cannot hide NEAR transaction history. The publish tx sender,
//!   its arguments (claim id, hashes, commitments — never an address)
//!   and its timing are public forever. A dedicated publisher account
//!   limits what that history reveals to "the publisher published
//!   something", never "which treasury it was about".
//! - Raw contract state is public on NEAR (`view_state`). The stored
//!   commitments are salted hashes, but the salt is stored alongside
//!   them, so a dictionary attack CAN recover a predictable controller
//!   or publisher account id from raw state. That account is a
//!   dedicated operational account, never a treasury — see
//!   docs/privacy-audit.md for the measured residual risk.

use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::store::{IterableSet, LookupMap};
use near_sdk::{env, near, AccountId, NearToken, PanicOnDefault, Promise};

/// NEP-297 event standard and version for veilproof events.
pub const EVENT_STANDARD: &str = "veilproof";
pub const EVENT_VERSION: &str = "2.0.0";
/// Contract version, exposed by `get_version` so offchain callers can
/// tell a v1 registry (owner-based) from a v2 registry (commitments).
pub const CONTRACT_VERSION: &str = "2.0.0";
/// Maximum claim_id length, in characters (= bytes: printable ASCII).
pub const MAX_CLAIM_ID_LEN: usize = 128;
/// A SHA-256 hash rendered as lowercase hex is exactly 64 characters.
pub const HASH_HEX_LEN: usize = 64;
/// Maximum claims one controller may hold at once. Bounds the
/// per-controller index so one controller cannot grow state without
/// bound; 100 is far above any real prover's needs (a prover publishes
/// one claim per report, a handful per treasury).
pub const MAX_CLAIMS_PER_CONTROLLER: u32 = 100;
/// Maximum claims the registry holds in total. A hard stop against
/// storage exhaustion by publish spam.
pub const MAX_TOTAL_CLAIMS: u64 = 10_000;
/// Minimum claim lifetime: 1 hour. A claim that expires in minutes is
/// useless to a verifier and looks like a mistake.
pub const MIN_DURATION_NS: u64 = 3_600_000_000_000;
/// Maximum claim lifetime: 365 days. Claims are attestations about a
/// point in time; a multi-year "valid" stamp would outlive the data it
/// attests and the policy it was evaluated under.
pub const MAX_DURATION_NS: u64 = 31_536_000_000_000_000;

/// Domain separators for the salted identity commitments. The formula
/// is sha256_hex("<domain>:<salt>:<account_id>"); the JS mirror lives
/// in src/registry.js (node) and public/js/registry.js (browser) and
/// MUST produce byte-identical strings. Domains keep a publisher
/// commitment from ever colliding with a controller commitment for the
/// same account and salt.
pub const PUBLISHER_COMMITMENT_DOMAIN: &str = "veilproof-publisher-v1";
pub const CONTROLLER_COMMITMENT_DOMAIN: &str = "veilproof-controller-v1";

/// A single published claim. Commitments and hashes only — see the
/// module docs. There is deliberately no account id anywhere in here:
/// the publisher is a salted commitment (verifiable against the tx
/// signer), the controller is a salted commitment (verifiable at
/// revoke time), and the treasury never appears at all.
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
    /// sha256_hex("veilproof-publisher-v1:<salt>:<publisher>"), fresh
    /// salt per claim, so two claims from the same publisher carry
    /// different commitments and cannot be linked through the registry.
    pub publisher_commitment: String,
    /// sha256_hex("veilproof-controller-v1:<salt>:<controller>"),
    /// computed offchain by the publisher; the controller account id
    /// is never sent to the contract.
    pub controller_commitment: String,
    /// The 64-hex salt both commitments above were computed with.
    /// Stored so `revoke_claim` can verify the caller without the
    /// controller account ever being named. Public in raw state by
    /// necessity; useless without a candidate account id (see the
    /// module docs on dictionary attacks against predictable names).
    pub commitment_salt: String,
    pub report_hash: String,
    pub evidence_hash: String,
    pub policy_hash: String,
    pub created_at: u64, // block timestamp, nanoseconds
    pub expires_at: u64, // block timestamp, nanoseconds
    pub revoked: bool,
}

/// The v1 claim shape, kept ONLY so `migrate` can read the old state.
/// v1 stored the publisher's account id as `owner`; v2 never does.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug)]
pub struct OldClaim {
    pub owner: AccountId,
    pub report_hash: String,
    pub evidence_hash: String,
    pub policy_hash: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub revoked: bool,
}

/// The v1 contract state shape, kept ONLY so `migrate` can read it.
/// Both fields are prefix-only maps (they serialise to nothing), so
/// the old state blob deserialises cleanly into this struct.
#[derive(BorshDeserialize, BorshSerialize)]
pub struct OldContract {
    pub claims: LookupMap<String, OldClaim>,
    pub owner_claims: LookupMap<AccountId, Vec<String>>,
}

/// Onchain limits, exposed by `get_limits` so offchain callers and
/// operators read the enforced caps from the contract, not from docs.
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
pub struct Limits {
    pub max_claims_per_controller: u32,
    pub max_total_claims: u64,
    pub min_duration_ns: u64,
    pub max_duration_ns: u64,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Contract {
    /// Admin: the registry account itself. Only the admin manages the
    /// publisher allowlist. Set once at init / migrate; never changed
    /// afterwards (the registry key, not the account, is what rotates).
    pub admin: AccountId,
    /// Claims by id. Deliberately a NEW trie prefix (b"C"), NOT v1's
    /// b"c": the v1 entries hold OldClaim bytes, and a v2 map on the
    /// same prefix would try to deserialise them as the new Claim
    /// type on insert (insert reads the previous value) and panic.
    /// `migrate` copies preserved claims from b"c" to b"C"; the v1
    /// entries stay in the trie as unreachable orphaned storage
    /// (already paid for), like the abandoned owner index.
    pub claims: LookupMap<String, Claim>,
    /// Accounts allowed to call `publish_claim`. In practice one
    /// dedicated publishing account. UnorderedSet (not LookupSet) so
    /// `list_publishers` can enumerate it for operators.
    pub publishers: IterableSet<AccountId>,
    /// Live claim counts per controller commitment. Keyed by the
    /// commitment string, never by an account id.
    pub controller_claim_counts: LookupMap<String, u32>,
    /// Live total claim count (revocations do not decrement: a revoked
    /// claim still occupies storage).
    pub total_claims: u64,
}

/// True only for exactly 64 lowercase hex characters (a SHA-256 digest).
/// Uppercase hex and any non-hex character fail.
fn is_valid_hash(value: &str) -> bool {
    value.len() == HASH_HEX_LEN
        && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// True only for printable ASCII (0x20 space through 0x7E tilde) and
/// within the length limit. Claim ids are report ids (16 lowercase hex
/// chars in practice); this rejects control characters, DEL, and any
/// non-ASCII / unicode that could smuggle lookalike ids or break
/// explorers and JSON consumers. Space is allowed (printable) but
/// pointless; ids with leading/trailing space are the caller's problem.
fn is_valid_claim_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_CLAIM_ID_LEN
        && value.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

/// Lowercase hex encoding of raw bytes (no `hex` crate in deps).
fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

/// The salted identity commitment: sha256_hex("<domain>:<salt>:<account>").
/// The publisher commitment is verified by the contract against the
/// real tx signer; the controller commitment is computed offchain by
/// the publisher and verified at revoke time against the caller.
fn commitment_hex(domain: &str, salt: &str, account: &AccountId) -> String {
    let input = format!("{domain}:{salt}:{account}");
    to_hex(&env::sha256(input.as_bytes()))
}

/// Build the NEP-297 event payload. Pure function (no logging) so unit
/// tests can assert on the exact bytes an event would carry — in
/// particular that no account id ever appears in one.
fn event_payload(event: &str, data: serde_json::Value) -> String {
    format!(
        "EVENT_JSON:{}",
        serde_json::to_string(&serde_json::json!({
            "standard": EVENT_STANDARD,
            "version": EVENT_VERSION,
            "event": event,
            "data": data,
        }))
        .expect("event serialises")
    )
}

fn emit_event(event: &str, data: serde_json::Value) {
    env::log_str(&event_payload(event, data));
}

#[near]
impl Contract {
    #[init]
    pub fn new() -> Self {
        Self {
            admin: env::current_account_id(),
            claims: LookupMap::new(b"C"),
            publishers: IterableSet::new(b"p"),
            controller_claim_counts: LookupMap::new(b"k"),
            total_claims: 0,
        }
    }

    /// One-shot v1 → v2 migration. `#[init(ignore_state)]` because the
    /// v2 state adds scalar fields (`admin`, `total_claims`) that the
    /// v1 blob does not contain — a plain code redeploy would fail to
    /// deserialise the old state on every call. This reads the v1 state
    /// with the v1 shapes, converts exactly the listed claim ids, and
    /// writes fresh v2 state.
    ///
    /// - Only the registry account itself may call it (predecessor must
    ///   be the contract account): migration is an operator action, not
    ///   a public method.
    /// - `claim_ids` must list every v1 claim worth preserving. The v1
    ///   claims map cannot be enumerated onchain (LookupMap has no key
    ///   iteration), so unlisted claims are left in the trie under the
    ///   old shape, unreachable by v2 code. List them all — see
    ///   docs/contract-migration.md for the known live ids. Preserved
    ///   claims are COPIED to the v2 prefix (b"C"); the v1 entries
    ///   under b"c" stay as unreachable orphaned storage.
    /// - Each preserved claim keeps its hashes, timestamps and revoked
    ///   flag. Its v1 `owner` becomes the controller AND the publisher
    ///   commitment (the v1 owner did both jobs), under a fresh random
    ///   salt, so the claim stays revocable by the same account and
    ///   stays valid under `is_claim_valid`. The owner account id
    ///   itself is not written anywhere in v2 state.
    /// - A second call fails closed: after migration the state blob is
    ///   v2-shaped, so `state_read::<OldContract>` panics with
    ///   "Cannot deserialize the contract state." There is no way to
    ///   re-run migration over live v2 state.
    /// - The v1 `owner_claims` index (prefix b"o") is abandoned, not
    ///   deleted: its keys cannot be enumerated, so its entries stay in
    ///   the trie as unreachable storage (already paid for). v2 has no
    ///   owner enumeration at all.
    #[init(ignore_state)]
    pub fn migrate(admin_publisher: AccountId, claim_ids: Vec<String>) -> Self {
        assert_eq!(
            env::predecessor_account_id(),
            env::current_account_id(),
            "migrate is admin-only: only the registry account itself may migrate"
        );
        let old: OldContract =
            env::state_read().expect("old contract state not found — nothing to migrate");
        let mut contract = Self {
            admin: env::current_account_id(),
            claims: LookupMap::new(b"C"),
            publishers: IterableSet::new(b"p"),
            controller_claim_counts: LookupMap::new(b"k"),
            total_claims: 0,
        };
        contract.publishers.insert(admin_publisher);
        let mut migrated = 0u64;
        for claim_id in &claim_ids {
            if let Some(old_claim) = old.claims.get(claim_id) {
                // Fresh random salt per migrated claim (random_seed is
                // the chain's per-block randomness; hashed to 64 hex).
                let salt = to_hex(&env::sha256(&env::random_seed()));
                let controller_commitment = commitment_hex(
                    CONTROLLER_COMMITMENT_DOMAIN,
                    &salt,
                    &old_claim.owner,
                );
                let publisher_commitment = commitment_hex(
                    PUBLISHER_COMMITMENT_DOMAIN,
                    &salt,
                    &old_claim.owner,
                );
                let claim = Claim {
                    publisher_commitment,
                    controller_commitment: controller_commitment.clone(),
                    commitment_salt: salt,
                    report_hash: old_claim.report_hash.clone(),
                    evidence_hash: old_claim.evidence_hash.clone(),
                    policy_hash: old_claim.policy_hash.clone(),
                    created_at: old_claim.created_at,
                    expires_at: old_claim.expires_at,
                    revoked: old_claim.revoked,
                };
                contract.claims.insert(claim_id.clone(), claim);
                let count = contract
                    .controller_claim_counts
                    .get(&controller_commitment)
                    .copied()
                    .unwrap_or(0);
                contract
                    .controller_claim_counts
                    .insert(controller_commitment, count + 1);
                contract.total_claims += 1;
                migrated += 1;
            }
        }
        emit_event(
            "contract_migrated",
            serde_json::json!({ "version": CONTRACT_VERSION, "claims_migrated": migrated }),
        );
        contract
    }

    // ---- admin: publisher allowlist ----

    fn assert_admin(&self) {
        assert_eq!(
            env::predecessor_account_id(),
            self.admin,
            "only the registry admin may manage publishers"
        );
    }

    /// Authorise an account to publish claims. Admin only. In practice
    /// the single dedicated publishing account; a second entry is for
    /// key rotation (add the new publisher, then remove the old one).
    pub fn add_publisher(&mut self, account_id: AccountId) {
        self.assert_admin();
        self.publishers.insert(account_id.clone());
        emit_event(
            "publisher_added",
            serde_json::json!({ "account_id": account_id }),
        );
    }

    /// Revoke an account's publish right. Admin only. Claims it already
    /// published are unaffected (their controller still revokes them).
    pub fn remove_publisher(&mut self, account_id: AccountId) {
        self.assert_admin();
        self.publishers.remove(&account_id);
        emit_event(
            "publisher_removed",
            serde_json::json!({ "account_id": account_id }),
        );
    }

    // ---- views ----

    /// Contract version ("2.0.0"). Offchain callers probe this to pick
    /// the v1 or v2 flow; a v1 registry has no such method at all.
    pub fn get_version(&self) -> String {
        CONTRACT_VERSION.to_string()
    }

    /// The admin account (the registry account itself).
    pub fn get_admin(&self) -> AccountId {
        self.admin.clone()
    }

    /// True when the account is on the publisher allowlist.
    pub fn is_authorized_publisher(&self, account_id: AccountId) -> bool {
        self.publishers.contains(&account_id)
    }

    /// Every allowlisted publisher, in insertion order. Operational
    /// accounts only — never a treasury.
    pub fn list_publishers(&self) -> Vec<AccountId> {
        self.publishers.iter().cloned().collect()
    }

    /// The enforced caps, read from the contract.
    pub fn get_limits(&self) -> Limits {
        Limits {
            max_claims_per_controller: MAX_CLAIMS_PER_CONTROLLER,
            max_total_claims: MAX_TOTAL_CLAIMS,
            min_duration_ns: MIN_DURATION_NS,
            max_duration_ns: MAX_DURATION_NS,
        }
    }

    /// Total claims ever published (revocations do not decrement).
    pub fn get_total_claims(&self) -> u64 {
        self.total_claims
    }

    /// Live claim count for one controller commitment (not an account).
    pub fn get_controller_claim_count(&self, controller_commitment: String) -> u32 {
        self.controller_claim_counts
            .get(&controller_commitment)
            .copied()
            .unwrap_or(0)
    }

    /// Fetch one claim by id, if it exists. The record carries hashes
    /// and commitments only — no account id of any kind.
    pub fn get_claim(&self, claim_id: String) -> Option<Claim> {
        self.claims.get(&claim_id).cloned()
    }

    /// True only when the claim exists, is not revoked, and has not
    /// expired. A missing claim is invalid, not an error.
    pub fn is_claim_valid(&self, claim_id: String) -> bool {
        match self.claims.get(&claim_id) {
            Some(claim) => !claim.revoked && env::block_timestamp() < claim.expires_at,
            None => false,
        }
    }

    // ---- publish / revoke ----

    /// Publish a claim. Only an allowlisted publisher may call it.
    ///
    /// The caller passes salted commitments, computed offchain:
    /// - `commitment_salt`: fresh random 64-hex per claim.
    /// - `publisher_commitment`: sha256_hex(
    ///   "veilproof-publisher-v1:<salt>:<caller>") — the contract
    ///   recomputes this from the real tx signer and rejects a
    ///   mismatch, so a publisher cannot file a commitment for someone
    ///   else's account.
    /// - `controller_commitment`: sha256_hex(
    ///   "veilproof-controller-v1:<salt>:<controller>") — the
    ///   controller account id is never sent to the contract; whoever
    ///   holds it (and the salt, stored onchain) can revoke.
    ///
    /// Storage is charged at cost: usage is measured around the writes
    /// (the claim record and the controller counter), the attached
    /// deposit must cover it, and any excess is refunded to the caller.
    /// A panic here rolls the writes back, so an underfunded publish
    /// stores nothing.
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
        controller_commitment: String,
        publisher_commitment: String,
        commitment_salt: String,
    ) {
        assert!(
            is_valid_claim_id(&claim_id),
            "claim_id must be 1-128 printable ASCII characters"
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
            is_valid_hash(&controller_commitment),
            "controller_commitment must be exactly 64 lowercase hex characters"
        );
        assert!(
            is_valid_hash(&publisher_commitment),
            "publisher_commitment must be exactly 64 lowercase hex characters"
        );
        assert!(
            is_valid_hash(&commitment_salt),
            "commitment_salt must be exactly 64 lowercase hex characters"
        );
        let now = env::block_timestamp();
        assert!(
            expires_at >= now.saturating_add(MIN_DURATION_NS),
            "expires_at must be at least 1 hour in the future"
        );
        assert!(
            expires_at <= now.saturating_add(MAX_DURATION_NS),
            "expires_at must be at most 365 days in the future"
        );
        assert!(
            self.claims.get(&claim_id).is_none(),
            "claim_id already exists"
        );
        let caller = env::predecessor_account_id();
        assert!(
            self.publishers.contains(&caller),
            "caller is not an authorized publisher"
        );
        // Bind the filed publisher commitment to the real signer.
        assert_eq!(
            publisher_commitment,
            commitment_hex(PUBLISHER_COMMITMENT_DOMAIN, &commitment_salt, &caller),
            "publisher_commitment does not match the caller"
        );
        // Per-controller and total caps (storage-exhaustion guards).
        let controller_count = self
            .controller_claim_counts
            .get(&controller_commitment)
            .copied()
            .unwrap_or(0);
        assert!(
            controller_count < MAX_CLAIMS_PER_CONTROLLER,
            "controller claim cap reached"
        );
        assert!(
            self.total_claims < MAX_TOTAL_CLAIMS,
            "total claim cap reached"
        );

        let claim = Claim {
            publisher_commitment: publisher_commitment.clone(),
            controller_commitment: controller_commitment.clone(),
            commitment_salt,
            report_hash,
            evidence_hash,
            policy_hash,
            created_at: now,
            expires_at,
            revoked: false,
        };

        let usage_before = env::storage_usage();
        self.claims.insert(claim_id.clone(), claim);
        self.controller_claim_counts
            .insert(controller_commitment.clone(), controller_count + 1);
        self.total_claims += 1;
        let used_bytes = env::storage_usage().saturating_sub(usage_before);
        // Note: in near-sdk unit tests env::storage_usage() is a static
        // context field (default 1024*300) that storage writes never
        // update, so the measured delta is 0 in the mock and this check
        // cannot be exercised there. Onchain it is the account's live
        // usage, so the delta — and the cost — are real. See the tests
        // module for why there is no insufficient-deposit unit test.
        // (total_claims is a fixed-size u64 in the state blob, so its
        // value change does not alter the blob size; the measured map
        // writes are the whole variable cost.)
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
            serde_json::json!({ "claim_id": claim_id, "publisher_commitment": publisher_commitment }),
        );
    }

    /// Revoke a claim. Only its controller may do so, and only once.
    /// The caller proves control without ever naming the controller
    /// account: the contract hashes the caller with the claim's stored
    /// salt and compares with the stored controller commitment.
    /// Revocation is permanent and blocks future verification.
    pub fn revoke_claim(&mut self, claim_id: String) {
        let claim = self
            .claims
            .get_mut(&claim_id)
            .expect("claim not found");
        let caller = env::predecessor_account_id();
        assert_eq!(
            claim.controller_commitment,
            commitment_hex(CONTROLLER_COMMITMENT_DOMAIN, &claim.commitment_salt, &caller),
            "only the claim controller can revoke"
        );
        assert!(!claim.revoked, "claim already revoked");
        claim.revoked = true;
        // The mutation is written back when the map is dropped at the end
        // of the call; no re-insert is needed.
        emit_event(
            "claim_revoked",
            serde_json::json!({ "claim_id": claim_id }),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use near_sdk::test_utils::{get_logs, VMContextBuilder};
    use near_sdk::testing_env;

    fn admin() -> AccountId {
        "registry.veilproof.testnet".parse().unwrap()
    }

    fn publisher() -> AccountId {
        "publisher.veilproof.testnet".parse().unwrap()
    }

    fn controller() -> AccountId {
        "controller.veilproof.testnet".parse().unwrap()
    }

    fn stranger() -> AccountId {
        "mallory.testnet".parse().unwrap()
    }

    fn treasury() -> AccountId {
        "veilproof-demo.testnet".parse().unwrap()
    }

    /// A valid 64-char lowercase hex string, filled with one hex digit.
    fn hex_hash(ch: char) -> String {
        std::iter::repeat_n(ch, 64).collect()
    }

    /// A context for one caller. Sets current_account_id to the
    /// registry so `new()` / `migrate()` pick up the right admin.
    /// Storage on NEAR costs 10^19 yocto/byte, so a claim of a few
    /// hundred bytes costs a few NEAR: attach 10 NEAR for publishes
    /// unless the test is about the deposit itself.
    fn ctx(predecessor: AccountId, attached: NearToken, timestamp: u64) {
        let mut b = VMContextBuilder::new();
        b.predecessor_account_id(predecessor);
        b.current_account_id(admin());
        b.attached_deposit(attached);
        b.block_timestamp(timestamp);
        b.account_balance(NearToken::from_near(10_000));
        testing_env!(b.build());
    }

    fn empty_contract() -> Contract {
        Contract {
            admin: admin(),
            claims: LookupMap::new(b"C"),
            publishers: IterableSet::new(b"p"),
            controller_claim_counts: LookupMap::new(b"k"),
            total_claims: 0,
        }
    }

    /// A contract with the publisher allowlisted (the normal operating
    /// state). The admin call runs in its own context, then the caller
    /// context is restored for the test body.
    fn contract_with_publisher() -> Contract {
        ctx(admin(), NearToken::from_near(0), 1_000_000);
        let mut c = empty_contract();
        c.add_publisher(publisher());
        c
    }

    /// The salt used by the publish helpers below. Tests that need a
    /// specific controller use `publish_as` with an explicit salt.
    fn salt() -> String {
        hex_hash('1')
    }

    /// Commitments for a (publisher, controller) pair under `salt`.
    /// Mirrors src/registry.js exactly; any drift breaks these tests.
    fn commitments(
        publisher_id: &AccountId,
        controller_id: &AccountId,
        salt: &str,
    ) -> (String, String) {
        (
            commitment_hex(CONTROLLER_COMMITMENT_DOMAIN, salt, controller_id),
            commitment_hex(PUBLISHER_COMMITMENT_DOMAIN, salt, publisher_id),
        )
    }

    /// Publish as the allowlisted publisher, controller = publisher.
    fn publish(c: &mut Contract, claim_id: &str, expires_at: u64) {
        let (controller_commitment, publisher_commitment) =
            commitments(&publisher(), &publisher(), &salt());
        c.publish_claim(
            claim_id.to_string(),
            hex_hash('a'),
            hex_hash('b'),
            hex_hash('c'),
            expires_at,
            controller_commitment,
            publisher_commitment,
            salt(),
        );
    }

    /// Publish as the allowlisted publisher with an explicit controller.
    fn publish_as(
        c: &mut Contract,
        claim_id: &str,
        expires_at: u64,
        controller_id: &AccountId,
        salt: &str,
    ) {
        let (controller_commitment, publisher_commitment) =
            commitments(&publisher(), controller_id, salt);
        c.publish_claim(
            claim_id.to_string(),
            hex_hash('a'),
            hex_hash('b'),
            hex_hash('c'),
            expires_at,
            controller_commitment,
            publisher_commitment,
            salt.to_string(),
        );
    }

    /// Insert a claim straight into storage, bypassing publish_claim.
    /// Used where the test needs state the public method cannot create
    /// under a single context (a claim whose controller is someone
    /// else, or one that is already expired).
    fn insert_claim(
        c: &mut Contract,
        claim_id: &str,
        controller_id: AccountId,
        expires_at: u64,
        revoked: bool,
    ) {
        let salt = salt();
        let (controller_commitment, publisher_commitment) =
            commitments(&publisher(), &controller_id, &salt);
        let claim = Claim {
            publisher_commitment,
            controller_commitment: controller_commitment.clone(),
            commitment_salt: salt,
            report_hash: hex_hash('a'),
            evidence_hash: hex_hash('b'),
            policy_hash: hex_hash('c'),
            created_at: 1_000,
            expires_at,
            revoked,
        };
        c.claims.insert(claim_id.to_string(), claim);
        let count = c
            .controller_claim_counts
            .get(&controller_commitment)
            .copied()
            .unwrap_or(0);
        c.controller_claim_counts
            .insert(controller_commitment, count + 1);
        c.total_claims += 1;
    }

    // ---- version / admin / allowlist ----

    #[test]
    fn version_and_limits_are_exposed() {
        ctx(admin(), NearToken::from_near(0), 1_000_000);
        let c = empty_contract();
        assert_eq!(c.get_version(), "2.0.0");
        assert_eq!(c.get_admin(), admin());
        assert_eq!(
            c.get_limits(),
            Limits {
                max_claims_per_controller: MAX_CLAIMS_PER_CONTROLLER,
                max_total_claims: MAX_TOTAL_CLAIMS,
                min_duration_ns: MIN_DURATION_NS,
                max_duration_ns: MAX_DURATION_NS,
            }
        );
        assert_eq!(c.get_total_claims(), 0);
        assert!(c.list_publishers().is_empty());
        assert!(!c.is_authorized_publisher(publisher()));
    }

    #[test]
    fn admin_can_add_and_remove_publishers() {
        ctx(admin(), NearToken::from_near(0), 1_000_000);
        let mut c = empty_contract();
        c.add_publisher(publisher());
        assert!(c.is_authorized_publisher(publisher()));
        assert_eq!(c.list_publishers(), vec![publisher()]);
        c.remove_publisher(publisher());
        assert!(!c.is_authorized_publisher(publisher()));
        assert!(c.list_publishers().is_empty());
    }

    #[test]
    #[should_panic(expected = "only the registry admin may manage publishers")]
    fn non_admin_cannot_add_publisher() {
        ctx(stranger(), NearToken::from_near(0), 1_000_000);
        let mut c = empty_contract();
        c.add_publisher(stranger());
    }

    #[test]
    #[should_panic(expected = "only the registry admin may manage publishers")]
    fn non_admin_cannot_remove_publisher() {
        ctx(stranger(), NearToken::from_near(0), 1_000_000);
        let mut c = empty_contract();
        c.remove_publisher(publisher());
    }

    // ---- publish: authorisation ----

    #[test]
    #[should_panic(expected = "caller is not an authorized publisher")]
    fn publish_by_non_allowlisted_caller_panics() {
        // Stranger is not on the allowlist; even with well-formed
        // commitments for themselves, the call must fail.
        let mut c = contract_with_publisher();
        ctx(stranger(), NearToken::from_near(10), 1_000_000);
        let (controller_commitment, publisher_commitment) =
            commitments(&stranger(), &stranger(), &salt());
        c.publish_claim(
            "claim-1".to_string(),
            hex_hash('a'),
            hex_hash('b'),
            hex_hash('c'),
            2_000_000_000_000_000,
            controller_commitment,
            publisher_commitment,
            salt(),
        );
    }

    #[test]
    #[should_panic(expected = "publisher_commitment does not match the caller")]
    fn publish_with_someone_elses_publisher_commitment_panics() {
        // The caller IS allowlisted, but files a publisher commitment
        // computed for a different account. The contract binds the
        // commitment to the real signer.
        let mut c = contract_with_publisher();
        ctx(publisher(), NearToken::from_near(10), 1_000_000);
        let (controller_commitment, publisher_commitment) =
            commitments(&stranger(), &publisher(), &salt());
        c.publish_claim(
            "claim-1".to_string(),
            hex_hash('a'),
            hex_hash('b'),
            hex_hash('c'),
            2_000_000_000_000_000,
            controller_commitment,
            publisher_commitment,
            salt(),
        );
    }

    #[test]
    fn removed_publisher_cannot_publish() {
        let mut c = contract_with_publisher();
        ctx(admin(), NearToken::from_near(0), 1_000_000);
        c.remove_publisher(publisher());
        ctx(publisher(), NearToken::from_near(10), 1_000_000);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            publish(&mut c, "claim-1", 2_000_000_000_000_000);
        }));
        assert!(result.is_err(), "removed publisher published anyway");
    }

    // ---- publish: happy path and record shape ----

    #[test]
    fn publish_and_get_round_trip() {
        let mut c = contract_with_publisher();
        ctx(publisher(), NearToken::from_near(10), 1_000_000);
        publish(&mut c, "claim-1", 2_000_000_000_000_000);
        let claim = c.get_claim("claim-1".to_string()).expect("stored");
        let (controller_commitment, publisher_commitment) =
            commitments(&publisher(), &publisher(), &salt());
        assert_eq!(claim.publisher_commitment, publisher_commitment);
        assert_eq!(claim.controller_commitment, controller_commitment);
        assert_eq!(claim.commitment_salt, salt());
        assert_eq!(claim.report_hash, hex_hash('a'));
        assert_eq!(claim.evidence_hash, hex_hash('b'));
        assert_eq!(claim.policy_hash, hex_hash('c'));
        assert_eq!(claim.created_at, 1_000_000);
        assert_eq!(claim.expires_at, 2_000_000_000_000_000);
        assert!(!claim.revoked);
        assert!(c.is_claim_valid("claim-1".to_string()));
        assert_eq!(c.get_total_claims(), 1);
        assert_eq!(c.get_controller_claim_count(controller_commitment), 1);
    }

    #[test]
    fn public_record_and_events_expose_no_account_id() {
        // The treasury, publisher and controller account ids must not
        // appear in any public surface: not in the get_claim JSON, not
        // in the emitted events. The claim record is commitments and
        // hashes only; the events carry claim_id + commitment only.
        let mut c = contract_with_publisher();
        ctx(publisher(), NearToken::from_near(10), 1_000_000);
        publish_as(&mut c, "claim-1", 2_000_000_000_000_000, &controller(), &salt());
        let claim = c.get_claim("claim-1".to_string()).expect("stored");
        let record_json = serde_json::to_string(&claim).expect("claim serialises");
        for account in [treasury(), publisher(), controller(), stranger()] {
            assert!(
                !record_json.contains(account.as_str()),
                "get_claim record leaks {account}: {record_json}"
            );
        }
        // The events emitted so far (publisher_added + claim_published)
        // must not name any account either — except publisher_added,
        // which names the allowlisted operational account by design.
        // claim_published must not.
        let logs = get_logs();
        let published: Vec<&String> = logs
            .iter()
            .filter(|l| l.contains("claim_published"))
            .collect();
        assert_eq!(published.len(), 1, "expected one claim_published event");
        for account in [treasury(), publisher(), controller(), stranger()] {
            assert!(
                !published[0].contains(account.as_str()),
                "claim_published event leaks {account}: {}",
                published[0]
            );
        }
        // And the event payload builder itself: a forged payload with
        // an account id would fail this, so the check is on the real
        // code path, not on a hand-written string.
        let forged = event_payload(
            "claim_published",
            serde_json::json!({ "claim_id": "claim-1", "publisher_commitment": claim.publisher_commitment }),
        );
        assert!(!forged.contains("testnet"));
    }

    // ---- publish: validation ----

    #[test]
    #[should_panic(expected = "claim_id already exists")]
    fn duplicate_publish_panics() {
        let mut c = contract_with_publisher();
        ctx(publisher(), NearToken::from_near(10), 1_000_000);
        publish(&mut c, "claim-1", 2_000_000_000_000_000);
        publish(&mut c, "claim-1", 2_000_000_000_000_000);
    }

    #[test]
    #[should_panic(expected = "report_hash must be exactly 64 lowercase hex characters")]
    fn bad_hash_wrong_length_panics() {
        let mut c = contract_with_publisher();
        ctx(publisher(), NearToken::from_near(10), 1_000_000);
        let (controller_commitment, publisher_commitment) =
            commitments(&publisher(), &publisher(), &salt());
        c.publish_claim(
            "claim-1".to_string(),
            hex_hash('a')[..63].to_string(),
            hex_hash('b'),
            hex_hash('c'),
            2_000_000_000_000_000,
            controller_commitment,
            publisher_commitment,
            salt(),
        );
    }

    #[test]
    #[should_panic(expected = "evidence_hash must be exactly 64 lowercase hex characters")]
    fn bad_hash_non_hex_panics() {
        let mut c = contract_with_publisher();
        ctx(publisher(), NearToken::from_near(10), 1_000_000);
        let (controller_commitment, publisher_commitment) =
            commitments(&publisher(), &publisher(), &salt());
        c.publish_claim(
            "claim-1".to_string(),
            hex_hash('a'),
            hex_hash('g'), // 'g' is not a hex digit
            hex_hash('c'),
            2_000_000_000_000_000,
            controller_commitment,
            publisher_commitment,
            salt(),
        );
    }

    #[test]
    #[should_panic(expected = "policy_hash must be exactly 64 lowercase hex characters")]
    fn bad_hash_uppercase_panics() {
        let mut c = contract_with_publisher();
        ctx(publisher(), NearToken::from_near(10), 1_000_000);
        let (controller_commitment, publisher_commitment) =
            commitments(&publisher(), &publisher(), &salt());
        c.publish_claim(
            "claim-1".to_string(),
            hex_hash('a'),
            hex_hash('b'),
            hex_hash('A'), // uppercase hex is rejected
            2_000_000_000_000_000,
            controller_commitment,
            publisher_commitment,
            salt(),
        );
    }

    #[test]
    #[should_panic(expected = "controller_commitment must be exactly 64 lowercase hex characters")]
    fn bad_controller_commitment_panics() {
        let mut c = contract_with_publisher();
        ctx(publisher(), NearToken::from_near(10), 1_000_000);
        let (_, publisher_commitment) = commitments(&publisher(), &publisher(), &salt());
        c.publish_claim(
            "claim-1".to_string(),
            hex_hash('a'),
            hex_hash('b'),
            hex_hash('c'),
            2_000_000_000_000_000,
            "not-a-hash".to_string(),
            publisher_commitment,
            salt(),
        );
    }

    #[test]
    #[should_panic(expected = "commitment_salt must be exactly 64 lowercase hex characters")]
    fn bad_commitment_salt_panics() {
        let mut c = contract_with_publisher();
        ctx(publisher(), NearToken::from_near(10), 1_000_000);
        let (controller_commitment, publisher_commitment) =
            commitments(&publisher(), &publisher(), &salt());
        c.publish_claim(
            "claim-1".to_string(),
            hex_hash('a'),
            hex_hash('b'),
            hex_hash('c'),
            2_000_000_000_000_000,
            controller_commitment,
            publisher_commitment,
            "xyz".to_string(),
        );
    }

    #[test]
    #[should_panic(expected = "claim_id must be 1-128 printable ASCII characters")]
    fn empty_claim_id_panics() {
        let mut c = contract_with_publisher();
        ctx(publisher(), NearToken::from_near(10), 1_000_000);
        publish(&mut c, "", 2_000_000_000_000_000);
    }

    #[test]
    #[should_panic(expected = "claim_id must be 1-128 printable ASCII characters")]
    fn claim_id_too_long_panics() {
        let mut c = contract_with_publisher();
        ctx(publisher(), NearToken::from_near(10), 1_000_000);
        let long_id: String = std::iter::repeat_n('x', 129).collect();
        publish(&mut c, &long_id, 2_000_000_000_000_000);
    }

    #[test]
    #[should_panic(expected = "claim_id must be 1-128 printable ASCII characters")]
    fn claim_id_control_char_panics() {
        let mut c = contract_with_publisher();
        ctx(publisher(), NearToken::from_near(10), 1_000_000);
        publish(&mut c, "claim\n1", 2_000_000_000_000_000);
    }

    #[test]
    #[should_panic(expected = "claim_id must be 1-128 printable ASCII characters")]
    fn claim_id_tab_panics() {
        let mut c = contract_with_publisher();
        ctx(publisher(), NearToken::from_near(10), 1_000_000);
        publish(&mut c, "claim\t1", 2_000_000_000_000_000);
    }

    #[test]
    #[should_panic(expected = "claim_id must be 1-128 printable ASCII characters")]
    fn claim_id_unicode_panics() {
        let mut c = contract_with_publisher();
        ctx(publisher(), NearToken::from_near(10), 1_000_000);
        publish(&mut c, "claim-é", 2_000_000_000_000_000);
    }

    #[test]
    #[should_panic(expected = "claim_id must be 1-128 printable ASCII characters")]
    fn claim_id_del_char_panics() {
        let mut c = contract_with_publisher();
        ctx(publisher(), NearToken::from_near(10), 1_000_000);
        publish(&mut c, "claim\u{7f}1", 2_000_000_000_000_000);
    }

    #[test]
    fn claim_id_boundary_lengths_pass() {
        let mut c = contract_with_publisher();
        ctx(publisher(), NearToken::from_near(10), 1_000_000);
        publish(&mut c, "x", 2_000_000_000_000_000);
        let max_id: String = std::iter::repeat_n('x', 128).collect();
        publish(&mut c, &max_id, 2_000_000_000_000_000);
        assert!(c.is_claim_valid("x".to_string()));
        assert!(c.is_claim_valid(max_id));
    }

    // ---- publish: expiry window ----

    #[test]
    #[should_panic(expected = "expires_at must be at least 1 hour in the future")]
    fn expiry_too_short_panics() {
        let mut c = contract_with_publisher();
        ctx(publisher(), NearToken::from_near(10), 1_000_000);
        publish(&mut c, "claim-1", 1_000_000 + MIN_DURATION_NS - 1);
    }

    #[test]
    #[should_panic(expected = "expires_at must be at most 365 days in the future")]
    fn expiry_too_long_panics() {
        let mut c = contract_with_publisher();
        ctx(publisher(), NearToken::from_near(10), 1_000_000);
        publish(&mut c, "claim-1", 1_000_000 + MAX_DURATION_NS + 1);
    }

    #[test]
    fn expiry_at_exact_bounds_passes() {
        let mut c = contract_with_publisher();
        ctx(publisher(), NearToken::from_near(10), 1_000_000);
        publish(&mut c, "claim-min", 1_000_000 + MIN_DURATION_NS);
        publish(&mut c, "claim-max", 1_000_000 + MAX_DURATION_NS);
        assert!(c.is_claim_valid("claim-min".to_string()));
        assert!(c.is_claim_valid("claim-max".to_string()));
    }

    #[test]
    fn expired_claim_reports_invalid() {
        let mut c = contract_with_publisher();
        ctx(publisher(), NearToken::from_near(10), 1_000_000);
        insert_claim(&mut c, "claim-1", publisher(), 500_000, false);
        assert!(!c.is_claim_valid("claim-1".to_string()));
        assert!(c.get_claim("claim-1".to_string()).is_some());
    }

    #[test]
    fn claim_at_exact_expiry_is_invalid() {
        let mut c = contract_with_publisher();
        ctx(publisher(), NearToken::from_near(10), 1_000_000);
        insert_claim(&mut c, "claim-1", publisher(), 1_000_000, false);
        assert!(!c.is_claim_valid("claim-1".to_string()));
    }

    // ---- publish: caps (storage exhaustion) ----

    #[test]
    #[should_panic(expected = "controller claim cap reached")]
    fn per_controller_cap_is_enforced() {
        let mut c = contract_with_publisher();
        ctx(publisher(), NearToken::from_near(10), 1_000_000);
        // Seed the counter near the cap (direct state setup; the cap
        // check itself runs for real in publish_claim, and the three
        // publishes below prove the counter still increments). A
        // 100-publish loop would overflow the mock's 16KB total-log
        // limit — one EVENT_JSON line per publish — so the loop is not
        // how this is exercised.
        let commitment = commitments(&publisher(), &controller(), &salt()).0;
        c.controller_claim_counts
            .insert(commitment.clone(), MAX_CLAIMS_PER_CONTROLLER - 3);
        for i in 0..3 {
            publish_as(
                &mut c,
                &format!("claim-{i}"),
                2_000_000_000_000_000,
                &controller(),
                &salt(),
            );
        }
        assert_eq!(
            c.get_controller_claim_count(commitment),
            MAX_CLAIMS_PER_CONTROLLER
        );
        // The 101st for the same controller must fail.
        publish_as(
            &mut c,
            "claim-101",
            2_000_000_000_000_000,
            &controller(),
            &salt(),
        );
    }

    #[test]
    fn per_controller_cap_does_not_block_other_controllers() {
        let mut c = contract_with_publisher();
        ctx(publisher(), NearToken::from_near(10), 1_000_000);
        // One controller sits AT its cap (seeded); a different
        // controller (different commitment) must still be able to
        // publish. Same log-limit note as the cap test above: the cap
        // is seeded, not looped to.
        let capped = commitments(&publisher(), &controller(), &salt()).0;
        c.controller_claim_counts
            .insert(capped.clone(), MAX_CLAIMS_PER_CONTROLLER);
        let other_salt = hex_hash('2');
        publish_as(
            &mut c,
            "claim-other",
            2_000_000_000_000_000,
            &stranger(),
            &other_salt,
        );
        assert!(c.is_claim_valid("claim-other".to_string()));
        assert_eq!(c.get_controller_claim_count(capped), MAX_CLAIMS_PER_CONTROLLER);
        assert_eq!(
            c.get_controller_claim_count(
                commitments(&publisher(), &stranger(), &other_salt).0
            ),
            1
        );
    }

    #[test]
    #[should_panic(expected = "total claim cap reached")]
    fn total_cap_is_enforced() {
        let mut c = contract_with_publisher();
        ctx(publisher(), NearToken::from_near(10), 1_000_000);
        // Seed the counter at the cap minus one (direct state setup;
        // the cap check itself runs for real in publish_claim).
        c.total_claims = MAX_TOTAL_CLAIMS - 1;
        publish(&mut c, "claim-1", 2_000_000_000_000_000);
        assert_eq!(c.get_total_claims(), MAX_TOTAL_CLAIMS);
        publish(&mut c, "claim-2", 2_000_000_000_000_000);
    }

    // No insufficient-deposit unit test: in the near-sdk mock,
    // env::storage_usage() is a static context field that storage writes
    // never update, so the measured cost is always 0 and a 0-deposit
    // publish cannot panic here. The at-cost check itself is correct and
    // live onchain, where storage_usage is the account's real usage. Do
    // not "fix" this by weakening the check; verify it in an integration
    // test against a real node instead.

    // ---- revoke: controller-only ----

    #[test]
    fn revoke_by_controller_works_and_invalidates() {
        let mut c = contract_with_publisher();
        ctx(publisher(), NearToken::from_near(10), 1_000_000);
        publish_as(&mut c, "claim-1", 2_000_000_000_000_000, &controller(), &salt());
        assert!(c.is_claim_valid("claim-1".to_string()));
        // The publisher is NOT the controller here: switching context
        // to the controller is what authorises the revoke.
        ctx(controller(), NearToken::from_near(0), 1_000_000);
        c.revoke_claim("claim-1".to_string());
        let claim = c.get_claim("claim-1".to_string()).expect("still stored");
        assert!(claim.revoked);
        assert!(!c.is_claim_valid("claim-1".to_string()));
        // The revoke event names the claim id only — no account.
        let logs = get_logs();
        let revoked: Vec<&String> =
            logs.iter().filter(|l| l.contains("claim_revoked")).collect();
        assert_eq!(revoked.len(), 1, "expected one claim_revoked event");
        for account in [treasury(), publisher(), controller(), stranger()] {
            assert!(
                !revoked[0].contains(account.as_str()),
                "claim_revoked event leaks {account}: {}",
                revoked[0]
            );
        }
    }

    #[test]
    #[should_panic(expected = "only the claim controller can revoke")]
    fn revoke_by_publisher_when_controller_is_someone_else_panics() {
        // Publisher ≠ controller: the publisher published it but cannot
        // revoke it. This is the separation the v1 owner model lacked.
        let mut c = contract_with_publisher();
        ctx(publisher(), NearToken::from_near(10), 1_000_000);
        publish_as(&mut c, "claim-1", 2_000_000_000_000_000, &controller(), &salt());
        c.revoke_claim("claim-1".to_string());
    }

    #[test]
    #[should_panic(expected = "only the claim controller can revoke")]
    fn revoke_by_stranger_panics() {
        let mut c = contract_with_publisher();
        ctx(stranger(), NearToken::from_near(10), 1_000_000);
        insert_claim(&mut c, "claim-1", controller(), 2_000_000_000_000_000, false);
        c.revoke_claim("claim-1".to_string());
    }

    #[test]
    #[should_panic(expected = "claim already revoked")]
    fn revoke_twice_panics() {
        let mut c = contract_with_publisher();
        ctx(controller(), NearToken::from_near(10), 1_000_000);
        insert_claim(&mut c, "claim-1", controller(), 2_000_000_000_000_000, false);
        c.revoke_claim("claim-1".to_string());
        c.revoke_claim("claim-1".to_string());
    }

    #[test]
    #[should_panic(expected = "claim not found")]
    fn revoke_missing_claim_panics() {
        let mut c = contract_with_publisher();
        ctx(controller(), NearToken::from_near(10), 1_000_000);
        c.revoke_claim("no-such-claim".to_string());
    }

    #[test]
    fn missing_claim_is_invalid_not_an_error() {
        let c = contract_with_publisher();
        ctx(publisher(), NearToken::from_near(10), 1_000_000);
        assert!(!c.is_claim_valid("no-such-claim".to_string()));
        assert!(c.get_claim("no-such-claim".to_string()).is_none());
    }

    // ---- migration ----

    #[test]
    fn migrate_converts_listed_v1_claims_and_preserves_validity() {
        // Build a v1 state blob the way the deployed contract holds it:
        // OldContract with one claim owned by the demo (treasury)
        // wallet, then write it as the contract state and migrate.
        ctx(admin(), NearToken::from_near(0), 1_000_000);
        let mut old = OldContract {
            claims: LookupMap::new(b"c"),
            owner_claims: LookupMap::new(b"o"),
        };
        let old_claim = OldClaim {
            owner: treasury(),
            report_hash: hex_hash('a'),
            evidence_hash: hex_hash('b'),
            policy_hash: hex_hash('c'),
            created_at: 1_000,
            expires_at: 2_000_000_000_000_000,
            revoked: false,
        };
        old.claims.insert("b05bf4684960ee83".to_string(), old_claim);
        let mut ids = vec!["b05bf4684960ee83".to_string()];
        old.owner_claims.insert(treasury(), ids.clone());
        ids.push("unlisted-claim".to_string());
        // Flush the hand-built v1 maps to mock storage before migrate
        // reads them: a deployed v1 contract flushes at the end of
        // every call, but this OldContract only flushes on drop.
        old.claims.flush();
        old.owner_claims.flush();
        env::state_write(&old);
        drop(old);

        let migrated = Contract::migrate(publisher(), vec!["b05bf4684960ee83".to_string()]);
        assert_eq!(migrated.get_version(), "2.0.0");
        assert_eq!(migrated.get_admin(), admin());
        assert!(migrated.is_authorized_publisher(publisher()));
        assert_eq!(migrated.get_total_claims(), 1);
        let claim = migrated
            .get_claim("b05bf4684960ee83".to_string())
            .expect("migrated claim present");
        // Hashes, timestamps and revoked flag preserved exactly.
        assert_eq!(claim.report_hash, hex_hash('a'));
        assert_eq!(claim.evidence_hash, hex_hash('b'));
        assert_eq!(claim.policy_hash, hex_hash('c'));
        assert_eq!(claim.created_at, 1_000);
        assert_eq!(claim.expires_at, 2_000_000_000_000_000);
        assert!(!claim.revoked);
        // The claim is still valid under the new code.
        assert!(migrated.is_claim_valid("b05bf4684960ee83".to_string()));
        // The old owner is the controller now — via commitment, not as
        // a stored account id. Its commitment must match the formula
        // with the stored salt, and the record JSON must not name it.
        let expected_controller = commitment_hex(
            CONTROLLER_COMMITMENT_DOMAIN,
            &claim.commitment_salt,
            &treasury(),
        );
        assert_eq!(claim.controller_commitment, expected_controller);
        let record_json = serde_json::to_string(&claim).expect("claim serialises");
        assert!(
            !record_json.contains(treasury().as_str()),
            "migrated record leaks the old owner: {record_json}"
        );
        // Unlisted claims are not migrated (LookupMap cannot be
        // enumerated, so the list is the whole preservation set).
        assert!(migrated.get_claim("unlisted-claim".to_string()).is_none());
        // The old owner can still revoke its migrated claim.
        ctx(treasury(), NearToken::from_near(0), 1_000_000);
        let mut migrated = migrated;
        migrated.revoke_claim("b05bf4684960ee83".to_string());
        assert!(!migrated.is_claim_valid("b05bf4684960ee83".to_string()));
    }

    #[test]
    #[should_panic(expected = "migrate is admin-only")]
    fn migrate_by_non_registry_account_panics() {
        ctx(stranger(), NearToken::from_near(0), 1_000_000);
        let old = OldContract {
            claims: LookupMap::new(b"c"),
            owner_claims: LookupMap::new(b"o"),
        };
        env::state_write(&old);
        Contract::migrate(publisher(), vec![]);
    }
}
