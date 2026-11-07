# Registry v1 → v2 migration

Status: **EXECUTED 2026-11-07.** The v2 contract is deployed on
`registry.veilproof.testnet` (code hash `5BagTskCFZkCsbhyvP427hiujMAmnmwXvJCkA922o8S5`,
wasm sha256 `3e24a36ad6affc4130e962e881811cd1fcb36dfc2c100e17f769b5d744ecfd0a`),
migrated by tx `Fe8mDgcZrqHTnya7CHav2UDTaCCZgFgfiXenZe4hgJLd`
(`contract_migrated`, 7 claims). The v1 rollback wasm was rebuilt
from GitHub commit `9f3aa1801303` and reproduces the deployed v1 code
hash exactly (`73f95f7b…`, base58 `8oiS486L51Spfc3iGsWJkNK5iaw2UEQp21o1mJHLm4wD`);
it is kept at `contract/target/near/veilproof_registry-v1-rollback.wasm`
(local only, never pushed). The dedicated publisher
`publisher.veilproof.testnet` was created and funded with 0.5 NEAR.
The demo claim was republished under v2 as `2e8675fa662f06a4`
(tx `57GjE7cZM6QWTd3ToSyw6bCoXZjK3zWdoL3CXbF92hvk`, score 770 solid,
AI lend_with_limits, limit 3 NEAR, all 10 checks pass); the old
`b05bf4684960ee83` stays valid, superseded, never revoked. The
migration found 7 live claims, not the 5 listed in §2 — the extra two
are `7c063555730c20fb` (old v1 demo claim, valid) and
`6338dd5177383c8e` (revoked e2e claim), both enumerated onchain via
`get_owner_claims` and preserved. The plan below is kept as the
record of what was done.

## 1. Assessment: in-place upgrade is possible (with a migration call)

**Verdict: upgrade in place; no new registry account is needed.**

Why it works:

- The v1 state is two prefix-only maps (`claims` b"c",
  `owner_claims` b"o"). Prefix-only maps serialise to nothing, so the
  v1 state blob deserialises cleanly into the `OldContract` shape the
  v2 code keeps for exactly this purpose (unit-tested in
  `migrate_converts_listed_v1_claims_and_preserves_validity`).
- The v2 state adds scalar fields (`admin`, `total_claims`), so a
  plain code-only redeploy would NOT work: every call would fail to
  deserialise the old state. The `#[init(ignore_state)] migrate()`
  entry point exists for this reason — it reads the v1 state, converts
  the listed claims, and writes fresh v2 state.
- The v2 claims map uses a NEW trie prefix (b"C"), not v1's b"c".
  This is load-bearing: a v2 map on the same prefix would try to
  deserialise v1 `OldClaim` bytes as the new `Claim` type on insert
  (insert reads the previous value) and panic. With the new prefix
  there is no cross-type read anywhere in the migration. The v1
  entries under b"c" stay in the trie as unreachable orphaned storage
  (already paid for by the registry account), exactly like the
  abandoned `owner_claims` index.
- `migrate` is one-shot and fails closed on a second call: after
  migration the state blob is v2-shaped, so `state_read::<OldContract>`
  panics with "Cannot deserialize the contract state." There is no way
  to re-run migration over live v2 state.

Why it is not a plain redeploy:

- Between the code deploy and the `migrate` call the contract is
  bricked: the new code cannot deserialise the v1 state, so every
  view and call fails until `migrate` runs. The window must be
  minutes, in one operator session, with `migrate` prepared and
  rehearsed beforehand. The recovery if `migrate` fails is to
  redeploy the v1 wasm (rollback artifact — see §3), because the
  state blob is still v1-shaped until `migrate` succeeds.
- The v1 claims map cannot be enumerated onchain (`LookupMap` has no
  key iteration), so `migrate` takes an explicit `claim_ids` list.
  Unlisted claims are left under the old shape, unreachable by v2
  code. The known live ids are listed in §2 — list them all.

## 2. What gets preserved

Known live claims on `registry.veilproof.testnet`, all verified via
RPC `get_claim` on 2026-11-06 (all owned by
`veilproof-demo.testnet`, all unrevoked):

| claim_id | created | expires |
| --- | --- | --- |
| `b05bf4684960ee83` (live demo) | 2026-11-06 | ~2026-12-06 |
| `a41d9faaa0a19148` | 2026-11-06 | ~2026-12-06 |
| `86f237c0cf2e3fe6` | 2026-11-06 | ~2026-12-06 |
| `bf2518ecb0791e4a` | 2026-11-06 | ~2026-12-06 |
| `063feb0181ad5577` | 2026-11-06 | ~2026-12-06 |

Before migrating, re-check this list against the explorer
(`https://testnet.nearblocks.io/address/registry.veilproof.testnet`)
— the repo history is the only source for it, and a claim published
outside the repo's scripts would be missed. **Any id missing from
the `migrate` call is lost to v2** (still in the trie, unreachable).

What migration preserves per claim: `report_hash`,
`evidence_hash`, `policy_hash`, `created_at`, `expires_at`,
`revoked`. What changes: the v1 `owner` becomes the controller AND
the publisher commitment, under a fresh random salt — so the claim
stays revocable by the same account (`veilproof-demo.testnet`) and
stays valid under `is_claim_valid`. The owner account id itself is
not written anywhere in v2 state. This is deliberate: the migrated
demo claim keeps working (the task's "do not break the live demo
claim"), while the NEW demo claim published after migration uses the
dedicated publisher (§5).

Note the honesty limit: the old owner is already public — it is in
every v1 `get_claim` response ever served and in the publish
transactions' history forever. Migration cannot un-publish history.
What it removes is the owner field from all FUTURE reads and events.

## 3. Before you start (checklist)

1. **Build the v1 rollback wasm FIRST.** The v1 wasm binary is no
   longer on disk (the v2 build overwrote
   `contract/target/near/veilproof_registry.wasm`). Rebuild it from
   the v1 source on GitHub (`Otoyo4real/Veilproof-`, main branch at
   the last pre-v2 commit) with `cargo near build
   non-reproducible-wasm`, and keep it as
   `contract/target/near/veilproof_registry-v1-rollback.wasm`.
   Record the deployed code hash first (`near-cli` account state or
   RPC `view_account` for `registry.veilproof.testnet`); a rebuild
   from the same source should reproduce it.
2. **Create the dedicated publisher account**,
   `publisher.veilproof.testnet` (testnet only, VeilProof wallets
   only — never a Genesis wallet). Fund it with ~0.5 NEAR (covers
   many publishes at ~0.003–0.005 NEAR storage each + gas). Add it
   to `~/workspace/veilproof/.testnet-accounts.json` as `"publisher":
   { "accountId": "publisher.veilproof.testnet", "privateKey":
   "ed25519:..." }` (chmod 600 file, key never printed or committed).
   The publisher is its own controller for the demo claims; a
   separate controller account can be used later, but the demo flow
   uses publisher-as-controller.
3. **Rehearse `migrate` offchain.** `cargo test` in `contract/`
   covers it (unit + integration), including the exact live claim id
   `b05bf4684960ee83`. Do not rehearse against the live registry.
4. **Freeze publishes.** Nobody publishes between the code deploy
   and the `migrate` call — a publish in that window fails (bricked
   contract) and its claim id would need adding to the list.
5. **Have the registry key at hand.** `migrate` must be signed by
   the registry account itself (`registry.veilproof.testnet` key in
   `.testnet-accounts.json` as `"registry"`). No other account can
   call it.

## 4. Procedure

All commands run from `~/workspace/veilproof`. Testnet only.

```sh
# 0. Sanity: the deployed registry is v1 and the demo claim is valid.
node -e "…" # or: check get_version is absent (v1 has no such method)
#    and is_claim_valid(b05bf4684960ee83) is true, get_claim returns owner veilproof-demo.testnet.

# 1. Build the v2 wasm (already built 2026-11-06; rebuild to confirm).
export PATH="$HOME/.cargo/bin:$PATH"
cd contract && cargo near build non-reproducible-wasm
#    expect target/near/veilproof_registry.wasm, sha256 3e24a36a…

# 2. Deploy the v2 CODE to the existing registry account.
#    This does NOT call new() and does NOT touch state — but from this
#    moment until step 3 the contract is bricked (v2 code cannot read
#    v1 state). Do step 3 immediately, in the same session.
node scripts/redeploy-registry.mjs
#    (deploys target/near/veilproof_registry.wasm; verifies the code
#    hash changed. Its post-checks call is_claim_valid/get_claim for a
#    missing id — those WILL FAIL while the contract is bricked, which
#    is expected: the script needs a v2-aware update, or run step 3
#    first and verify afterwards. See the note below.)

# 3. Migrate state (signed by the registry account itself).
#    Exact call — claim_ids is the full list from §2, admin_publisher
#    is the dedicated publisher account:
#    migrate({
#      admin_publisher: "publisher.veilproof.testnet",
#      claim_ids: [
#        "b05bf4684960ee83", "a41d9faaa0a19148", "86f237c0cf2e3fe6",
#        "bf2518ecb0791e4a", "063feb0181ad5577"
#      ]
#    })
#    (near-cli / near-api-js functionCall from the registry account,
#    no attached deposit, 100 TGas. No migrate script ships with this
#    change yet — write it as a small script mirroring
#    scripts/redeploy-registry.mjs, or call it from a one-off node
#    snippet. Do NOT call migrate twice.)

# 4. Verify the migration (all must pass; stop and roll back on any failure).
#    - get_version() == "2.0.0"
#    - get_admin() == "registry.veilproof.testnet"
#    - list_publishers() == ["publisher.veilproof.testnet"]
#    - get_total_claims() == 5
#    - get_claim("b05bf4684960ee83") returns the same report/evidence/
#      policy hashes as before, revoked false, and NO owner field
#    - is_claim_valid("b05bf4684960ee83") == true (and true for the other four)
#    - get_claim("does-not-exist") == null, is_claim_valid("does-not-exist") == false
#    - A publish from a non-allowlisted account fails with
#      "caller is not an authorized publisher" (check on a throwaway
#      claim id, no deposit needed — the call panics before charging).
```

Note on `scripts/redeploy-registry.mjs`: it was written for a
code-only v1→v1 fix and its post-deploy verification calls
`is_claim_valid`/`get_claim`. Against the v2 code pre-migration
those calls fail (bricked state), so either (a) update the script to
run the `migrate` call right after deploying and verify afterwards,
or (b) deploy with it, ignore the verification failure, run step 3,
then verify by hand. Option (a) is the right shape for the migration
run — fold it in when the migration script is written.

## 5. After migration: republish the live demo claim under the new model

The migrated `b05bf4684960ee83` stays valid onchain, superseded,
never revoked — the one-click demo keeps working through the
migration with zero downtime for verifiers. Then, as a separate
deliberate step, republish a fresh demo claim under the new model:

1. Run `node scripts/publish-demo-claim.mjs`. It probes the registry
   version: on v2 it publishes from the `publisher` account in
   `.testnet-accounts.json` (publisher-as-controller), asserts the
   `publisher_commitment` matches, and asserts there is no `owner`
   field. The report is rebuilt from live chain data, so it gets a
   new report id.
2. Confirm all 10 checks pass on the new claim (the script does this
   itself, step 7/7), then update the public references to the new
   report id: `public/demo-report.json` (written by the script),
   `README.md` (live demo claim line), `docs/privacy-audit.md`
   (live-demo line), and the landing page copy if it names the id.
3. Run the full checks: `npm test`, `npm run audit` (expect CLEAN
   under the v2 model), `cargo test` in `contract/`, and
   `node scripts/demo-e2e.mjs` (it exercises the v2 publish +
   revoke path end to end).
4. The old `b05bf4684960ee83` stays valid and is never revoked —
   same treatment as `a41d9faaa0a19148` received under P2/P3.

## 6. Breaking changes (for callers)

| Area | v1 | v2 |
| --- | --- | --- |
| `get_claim` | returns `owner: AccountId` | no account id; returns `publisher_commitment`, `controller_commitment`, `commitment_salt` (all 64-hex) |
| `get_owner_claims(owner)` | lists an owner's claim ids | **removed** — no enumeration exists any more |
| `publish_claim` args | 5 args, anyone may call, caller becomes owner | 8 args (adds `controller_commitment`, `publisher_commitment`, `commitment_salt`); caller must be allowlisted; publisher commitment must match the signer |
| `revoke_claim` | `claim_id` only; caller must equal `owner` | `claim_id` only (signature unchanged); caller must hash to the stored `controller_commitment` with the stored salt |
| Events | `claim_published`/`claim_revoked` carry `owner` | carry `claim_id` + `publisher_commitment` / `claim_id` only |
| Expiry | any future `expires_at` | 1 hour – 365 days from now |
| `claim_id` | non-empty, ≤128 chars | 1–128 **printable ASCII** chars (control/unicode/DEL rejected) |
| Caps | none | 100 claims per controller, 10,000 total |
| New views | — | `get_version`, `get_admin`, `is_authorized_publisher`, `list_publishers`, `get_limits`, `get_total_claims`, `get_controller_claim_count` |
| New admin methods | — | `add_publisher`, `remove_publisher` (admin = registry account only) |
| Website direct publish | any connected wallet could publish | only an allowlisted publisher; `public/app.js` probes the version and shows a clear message for ordinary wallets instead of submitting a rejected transaction. Publishing goes through the dedicated publisher (agent CLI) until/unless a relayer exists. |

JS callers are already updated and version-guarded
(`src/registry.js`, `public/js/registry.js`, `scripts/publish-demo-claim.mjs`,
`scripts/agent-prove.mjs`, `scripts/demo-e2e.mjs`, `public/app.js`):
against the deployed v1 registry they run the old flow unchanged;
against v2 they run the new flow. The live site keeps working until
migration, and keeps working after it for building and verifying —
only direct publishing changes, as above.

## 7. Rollback

- **Before `migrate` succeeds:** the state blob is still v1-shaped.
  Redeploy the v1 rollback wasm (§3.1) with
  `scripts/redeploy-registry.mjs` (point it at the rollback file).
  The contract is v1 again, claims untouched, demo claim valid.
- **After `migrate` succeeds:** there is no rollback to v1 state —
  the state blob is v2-shaped and v1 code cannot read it. The only
  way back would be a v2→v1 migration function, which does not
  exist. Treat `migrate` as the point of no return: verify §4 fully
  before announcing it, and keep the pre-migration RPC snapshots of
  all five claims (hashes above) as the ground truth to check
  against.
- **If `migrate` itself panics midway:** NEAR transactions are
  atomic — a panic rolls the whole call back, so state stays v1 and
  the code stays v2 (bricked). Fix the cause and call `migrate`
  again, or roll the code back to v1 per the first bullet.

## 8. Residual risks after migration (honest list)

- **Transaction history is public forever.** The publish tx sender
  (the dedicated publisher account), its timing, and its arguments
  (claim id, hashes, commitments — never an address) are visible on
  the explorer. A dedicated publisher limits what that reveals to
  "the publisher published something", never "which treasury it was
  about" — but claims published close together from the same
  publisher are trivially grouped by sender and timing. A relayer
  does not fix this either; it just moves the sender. See
  `docs/privacy-audit.md`.
- **Raw contract state is public.** Anyone can dump it with
  `view_state`. The stored commitments are salted hashes, but the
  salt is stored alongside them, so a dictionary attack CAN recover
  a predictable controller or publisher account id from raw state
  (the audit measures the report-level equivalent; the same
  reasoning applies). The recovered account is a dedicated
  operational account, never a treasury — that is the boundary the
  design defends.
- **The publisher allowlist is public** (`list_publishers`). That is
  by design: the publisher is an operational identity, not a secret.
- **Migrated legacy claims keep their old owner as controller**
  (via commitment). The old owner is already public from v1 history,
  so this preserves control without adding any new exposure — but it
  means the five legacy claims are still tied, by hash, to the demo
  wallet for anyone who bothers to dictionary-attack the salted
  commitment. The republished demo claim (§5) is the one that is
  clean under the new model.
- **Claim-id squatting is not prevented by the contract.** Report
  ids are 128-bit random, so guessing one is infeasible — but anyone
  who learns a report id before it is published (it travels in the
  public report, which is only shared when the prover chooses) can
  publish it first with their own commitments. The victim's report
  then fails to publish ("claim_id already exists") and the
  squatter's claim is unverifiable against the real report (hash
  mismatch). Keep report ids private until published.
- **A wrong `controller_commitment` locks a claim unrevocable.**
  The contract cannot verify the controller commitment (the account
  is never sent), so a publisher typo strands the claim — it can
  never be revoked, only expire (max 365 days). The publish scripts
  recompute the commitment from the known controller account and
  assert it after publishing; never publish with a hand-typed
  commitment.
