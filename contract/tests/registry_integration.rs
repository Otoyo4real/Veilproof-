// VeilProof registry integration tests — full public-API flows across
// caller contexts, against the real contract code.
//
// These run in the near-sdk mock (testing_env), not against a live
// node: every call executes the actual contract methods, with the
// caller switched between steps the way separate transactions would.
// A live-node check is a migration-verification step, not a unit of
// this suite — see docs/contract-migration.md. Nothing here asserts a
// hardcoded VERIFIED; every assertion reads state the contract itself
// produced.
//
// The mock's storage survives a second testing_env! call inside one
// test (verified by probe 2026-11-06), so a contract built in one
// context keeps its data when the caller switches.
use near_sdk::test_utils::{get_logs, VMContextBuilder};
use near_sdk::testing_env;
use near_sdk::{AccountId, NearToken};
use veilproof_registry::{
    Contract, OldClaim, OldContract, CONTROLLER_COMMITMENT_DOMAIN, CONTRACT_VERSION,
    MAX_CLAIMS_PER_CONTROLLER, PUBLISHER_COMMITMENT_DOMAIN,
};
use near_sdk::store::LookupMap;

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

fn hex_hash(ch: char) -> String {
    std::iter::repeat_n(ch, 64).collect()
}

fn ctx(predecessor: AccountId, attached: NearToken, timestamp: u64) {
    let mut b = VMContextBuilder::new();
    b.predecessor_account_id(predecessor);
    b.current_account_id(admin());
    b.attached_deposit(attached);
    b.block_timestamp(timestamp);
    b.account_balance(NearToken::from_near(10_000));
    testing_env!(b.build());
}

fn salt() -> String {
    hex_hash('1')
}

/// The commitment formula, reimplemented here from the spec
/// (sha256_hex("<domain>:<salt>:<account>")) so the test does not just
/// call the contract's own helper — an independent implementation
/// catching drift between the contract and the JS mirror.
fn commitment_hex(domain: &str, salt: &str, account: &AccountId) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(format!("{domain}:{salt}:{account}").as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn new_contract() -> Contract {
    ctx(admin(), NearToken::from_near(0), 1_000_000);
    let mut c = Contract::new();
    c.add_publisher(publisher());
    c
}

fn publish_args(controller_id: &AccountId, salt: &str) -> (String, String, String) {
    (
        commitment_hex(CONTROLLER_COMMITMENT_DOMAIN, salt, controller_id),
        commitment_hex(PUBLISHER_COMMITMENT_DOMAIN, salt, &publisher()),
        salt.to_string(),
    )
}

fn publish(
    c: &mut Contract,
    claim_id: &str,
    controller_id: &AccountId,
    salt: &str,
    expires_at: u64,
) {
    let (controller_commitment, publisher_commitment, commitment_salt) =
        publish_args(controller_id, salt);
    c.publish_claim(
        claim_id.to_string(),
        hex_hash('a'),
        hex_hash('b'),
        hex_hash('c'),
        expires_at,
        controller_commitment,
        publisher_commitment,
        commitment_salt,
    );
}

const FAR_FUTURE: u64 = 2_000_000_000_000_000; // ~2033, inside the 365d window from t=1_000_000? No — see below.

// Note: FAR_FUTURE is 2e15 ns from the epoch; the test timestamp is
// 1_000_000 ns, so the duration is ~2e15 ns ≈ 23 days: inside the
// 1h–365d window. The constant is a duration from genesis, not from now.

#[test]
fn full_lifecycle_across_callers() {
    let mut c = new_contract();
    assert_eq!(c.get_version(), CONTRACT_VERSION);

    // 1. Stranger cannot publish (not allowlisted).
    ctx(stranger(), NearToken::from_near(10), 1_000_000);
    let (cc, pc, salt_s) = publish_args(&controller(), &salt());
    let err = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        c.publish_claim(
            "claim-1".to_string(),
            hex_hash('a'),
            hex_hash('b'),
            hex_hash('c'),
            FAR_FUTURE,
            cc,
            pc,
            salt_s,
        );
    }));
    assert!(err.is_err(), "stranger published a claim");

    // 2. Allowlisted publisher publishes; controller is a third account.
    ctx(publisher(), NearToken::from_near(10), 1_000_000);
    publish(&mut c, "claim-1", &controller(), &salt(), FAR_FUTURE);
    assert!(c.is_claim_valid("claim-1".to_string()));

    // 3. Duplicate publish fails (squatting / collision).
    let err = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        publish(&mut c, "claim-1", &controller(), &salt(), FAR_FUTURE);
    }));
    assert!(err.is_err(), "duplicate claim_id published");

    // 4. Publisher cannot revoke — it is not the controller.
    let err = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        c.revoke_claim("claim-1".to_string());
    }));
    assert!(err.is_err(), "publisher revoked a claim it does not control");

    // 5. Stranger cannot revoke either.
    ctx(stranger(), NearToken::from_near(0), 1_000_000);
    let err = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        c.revoke_claim("claim-1".to_string());
    }));
    assert!(err.is_err(), "stranger revoked a claim");

    // 6. Controller revokes; the claim becomes invalid, permanently.
    ctx(controller(), NearToken::from_near(0), 1_000_000);
    c.revoke_claim("claim-1".to_string());
    assert!(!c.is_claim_valid("claim-1".to_string()));
    assert!(c.get_claim("claim-1".to_string()).unwrap().revoked);
    let err = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        c.revoke_claim("claim-1".to_string());
    }));
    assert!(err.is_err(), "double revoke succeeded");
}

#[test]
fn no_public_surface_names_any_account() {
    let mut c = new_contract();
    ctx(publisher(), NearToken::from_near(10), 1_000_000);
    publish(&mut c, "claim-1", &controller(), &salt(), FAR_FUTURE);

    // get_claim JSON must contain neither the treasury, the publisher,
    // nor the controller account id — only hashes and commitments.
    let claim = c.get_claim("claim-1".to_string()).expect("stored");
    let record_json = serde_json::to_string(&claim).expect("claim serialises");
    for account in [treasury(), publisher(), controller(), stranger()] {
        assert!(
            !record_json.contains(account.as_str()),
            "get_claim leaks {account}: {record_json}"
        );
    }
    // The stored commitments must equal the independently computed ones.
    assert_eq!(
        claim.publisher_commitment,
        commitment_hex(PUBLISHER_COMMITMENT_DOMAIN, &salt(), &publisher())
    );
    assert_eq!(
        claim.controller_commitment,
        commitment_hex(CONTROLLER_COMMITMENT_DOMAIN, &salt(), &controller())
    );
    // Events: claim_published / claim_revoked name the claim id and the
    // publisher commitment only — never an account.
    ctx(controller(), NearToken::from_near(0), 1_000_000);
    c.revoke_claim("claim-1".to_string());
    for log in get_logs() {
        if log.contains("claim_published") || log.contains("claim_revoked") {
            for account in [treasury(), publisher(), controller(), stranger()] {
                assert!(
                    !log.contains(account.as_str()),
                    "event leaks {account}: {log}"
                );
            }
        }
    }
    // Distinct salts give distinct commitments for the same publisher,
    // so two claims cannot be linked through the registry.
    ctx(publisher(), NearToken::from_near(10), 1_000_000);
    let other_salt = hex_hash('2');
    publish(&mut c, "claim-2", &controller(), &other_salt, FAR_FUTURE);
    let second = c.get_claim("claim-2".to_string()).expect("stored");
    assert_ne!(
        claim.publisher_commitment, second.publisher_commitment,
        "same publisher, different salt — commitments must differ"
    );
    assert_ne!(
        claim.controller_commitment, second.controller_commitment,
        "same controller, different salt — commitments must differ"
    );
}

#[test]
fn per_controller_cap_blocks_only_that_controller() {
    let mut c = new_contract();
    ctx(publisher(), NearToken::from_near(10), 1_000_000);
    // Seed controller A at its cap; A cannot publish, B can.
    let commitment_a = commitment_hex(CONTROLLER_COMMITMENT_DOMAIN, &salt(), &controller());
    c.controller_claim_counts
        .insert(commitment_a.clone(), MAX_CLAIMS_PER_CONTROLLER);
    let err = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        publish(&mut c, "claim-a", &controller(), &salt(), FAR_FUTURE);
    }));
    assert!(err.is_err(), "capped controller published");
    publish(&mut c, "claim-b", &stranger(), &hex_hash('2'), FAR_FUTURE);
    assert!(c.is_claim_valid("claim-b".to_string()));
    assert_eq!(c.get_total_claims(), 1);
}

#[test]
fn expired_claim_is_invalid_but_still_readable() {
    let mut c = new_contract();
    ctx(publisher(), NearToken::from_near(10), 1_000_000);
    // Publish with a short-but-legal lifetime, then move time past it.
    let expires_at = 1_000_000 + 3_600_000_000_000; // exactly the 1h minimum
    publish(&mut c, "claim-1", &controller(), &salt(), expires_at);
    assert!(c.is_claim_valid("claim-1".to_string()));
    ctx(publisher(), NearToken::from_near(0), expires_at);
    assert!(!c.is_claim_valid("claim-1".to_string()));
    assert!(c.get_claim("claim-1".to_string()).is_some());
}

#[test]
fn migration_preserves_claims_then_new_model_takes_over() {
    // 1. Hand-build v1 state the way the deployed registry holds it.
    ctx(admin(), NearToken::from_near(0), 1_000_000);
    let mut old = OldContract {
        claims: LookupMap::new(b"c"),
        owner_claims: LookupMap::new(b"o"),
    };
    old.claims.insert(
        "b05bf4684960ee83".to_string(),
        OldClaim {
            owner: treasury(),
            report_hash: hex_hash('a'),
            evidence_hash: hex_hash('b'),
            policy_hash: hex_hash('c'),
            created_at: 1_000,
            expires_at: FAR_FUTURE,
            revoked: false,
        },
    );
    old.claims.flush();
    old.owner_claims.flush();
    near_sdk::env::state_write(&old);
    drop(old);

    // 2. Migrate (registry account only) with the known claim id.
    let mut migrated = Contract::migrate(publisher(), vec!["b05bf4684960ee83".to_string()]);
    assert!(migrated.is_claim_valid("b05bf4684960ee83".to_string()));
    assert!(migrated.is_authorized_publisher(publisher()));
    assert_eq!(migrated.get_total_claims(), 1);

    // 3. New-model publish works alongside the migrated claim, and the
    // old owner can still revoke its migrated claim.
    ctx(publisher(), NearToken::from_near(10), 1_000_000);
    publish(&mut migrated, "new-claim", &controller(), &salt(), FAR_FUTURE);
    assert!(migrated.is_claim_valid("new-claim".to_string()));
    assert_eq!(migrated.get_total_claims(), 2);
    ctx(treasury(), NearToken::from_near(0), 1_000_000);
    migrated.revoke_claim("b05bf4684960ee83".to_string());
    assert!(!migrated.is_claim_valid("b05bf4684960ee83".to_string()));
    assert!(migrated.is_claim_valid("new-claim".to_string()));
}
