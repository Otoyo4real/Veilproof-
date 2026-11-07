# Privacy audit

VeilProof's privacy claim is measured, not asserted. `npm run audit`
runs an attacker that receives **only public data** — the public
reports, the registry's public views (`get_claim` /
`get_owner_claims`), and public API responses — and tries to:

- (a) **recover a wallet address** by hashing a dictionary of
  plausible names and comparing with the prover commitments;
- (b) **link two reports to the same prover**, by identical prover
  commitment, and separately by the registry's public owner field;
- (c) **estimate the exact aggregate balance and exact score** from
  the public report.

The run is over **50 simulated provers, 2 reports each (100 total)**,
with a seeded RNG so the table is reproducible. Five of the provers
use readable names from the attacker's dictionary (real agents pick
readable names); the other 45 use random subaccount names. The audit
also runs the same attacks on the live demo claim
(`public/demo-report.json`).

The audit is a measurement, not a gate: it always exits 0 and prints
its verdict. The tests in `test/privacy-audit.test.mjs` are the gate —
they assert 0 address recoveries and linking no better than chance.

## Results — BEFORE the P2/P3 fixes (2026-11-06)

| Attack | Result | Chance / baseline | Verdict |
| --- | --- | --- | --- |
| (a) Address recovery (dictionary) | 5/50 recovered — 0/45 random, 5/5 named | — | LEAK |
| (b) Linking via prover commitment | precision 100.0% | chance 1.0% | LEAK |
| (b) Linking via registry owner field | precision 100.0% | chance 1.0% | LEAK (documented limit) |
| (c) Balance estimate error (mean) | 0.00% | exact = 0% | LEAK |
| (c) Score estimate error (mean) | 0.00% | exact = 0% | LEAK |
| Live demo claim `a41d9faaa0a19148` | dictionary recovery YES, exact balance visible YES, exact score visible YES (770) | — | LEAK |

What each leak means:

- **Address recovery (5/5 named):** an unsalted `sha256(address)`
  commitment is reversible for any predictable name — the attacker
  just hashes the dictionary. Random names survive, readable names
  don't. Fixed by P2 (fresh random salt per report, commitment over
  salt + address; the salt travels only in the disclosure package).
- **Linking via commitment (100% vs 1% chance):** two reports from
  the same treasury share the identical prover commitment, so they
  are trivially matchable from public data. Fixed by P2 (fresh
  commitments per report).
- **Exact balance / score (0.00% error):** the public report's claim
  values are the exact measured amounts in yocto, and `score.value`
  is the exact score. Anyone reading the report knows both exactly.
  Fixed by P3 (predicate disclosure: public claims carry thresholds
  and bands only; exact values stay in the private disclosure).
- **Linking via registry owner field (100% vs 1% chance):** the
  registry's `get_claim` returns the owner account, and
  `get_owner_claims` lists every claim an owner published. This is
  public by design — revocation needs an owner — so **salts do not
  fix it**. It is a documented limit, not a bug to be fixed in this
  sprint: report-level unlinkability (P2) holds, registry-level
  linking by owner remains. A contract change (owner as a commitment
  plus a signature-based revoke) would be needed to remove it, and
  is future work.

## Results — AFTER P2 (salts), BEFORE P3 (2026-11-06)

P2 fixed the commitment leaks. The exact-value leaks remain until P3.

| Attack | Result | Chance / baseline | Verdict |
| --- | --- | --- | --- |
| (a) Address recovery (dictionary) | 0/50 recovered — 0/45 random, 0/5 named | — | PASS |
| (b) Linking via prover commitment | no clusters at all (every report has a unique commitment) | chance 1.0% | PASS |
| (b) Linking via registry owner field | precision 100.0% | chance 1.0% | LEAK (documented limit) |
| (c) Balance estimate error (mean) | 0.00% | exact = 0% | LEAK — P3 |
| (c) Score estimate error (mean) | 0.00% | exact = 0% | LEAK — P3 |
| Live demo claim `a41d9faaa0a19148` | dictionary recovery YES, exact balance visible YES, exact score visible YES (770) | — | LEAK — old pre-P2 report; P3 republishes it |

## Results — AFTER P3 (predicates), 2026-11-06

P3 strips exact values from the public report (claims keep `{ id, passed, threshold }`, score keeps `{ version, band, components }` without `value`/`points`). The attacker can now only read thresholds and bands.

| Attack | Result | Chance / baseline | Verdict |
| --- | --- | --- | --- |
| (a) Address recovery (dictionary) | 0/50 recovered — 0/45 random, 0/5 named | — | PASS |
| (b) Linking via prover commitment | no clusters at all (every report has a unique commitment) | chance 1.0% | PASS |
| (b) Linking via registry owner field | precision 100.0% | chance 1.0% | LEAK (documented limit) |
| (c) Balance estimate error (mean) | 94.04% | exact = 0% | PASS |
| (c) Score estimate error (mean) | 6.22% | exact = 0% | PASS |
| Live demo claim `a41d9faaa0a19148` | dictionary recovery YES, exact balance visible YES, exact score visible YES (770) | — | LEAK — old pre-P2/pre-P3 report; republication below replaces it |

The balance estimator now reads the claim threshold (1 NEAR) instead of the exact balance (2–50 NEAR), so it underestimates by 94% on average. The score estimator reads the band midpoint (e.g. 700 for solid) instead of the exact score, so it errs by 6.22% on average — small, because bands are 200–300 points wide, but it is a bound, not the number, and the exact score is no longer published anywhere.

## Demo claim republished (P2 + P3), 2026-11-06

New live demo claim `b05bf4684960ee83`, publish tx `3ouNst9DcYkcptEpua7EzqdLDmuY8P8uFsKRgU9TW9PQ` (script `scripts/publish-demo-claim.mjs`, salts + predicate format). The audit's live-claim line now reads: dictionary recovery **no**, exact balance visible **no**, exact score visible **no**. The old claim `a41d9faaa0a19148` stays valid onchain, superseded, never revoked. The landing-page mock report and README now show the new claim in predicate form (Pass + threshold, band only).

## Demo claim republished (registry v2), 2026-11-07

Registry migrated v1 to v2 (`docs/contract-migration.md`): 7 claims migrated, no owner field anywhere in v2. New live demo claim `2e8675fa662f06a4`, publish tx `57GjE7cZM6QWTd3ToSyw6bCoXZjK3zWdoL3CXbF92hvk`, published from the dedicated publisher `publisher.veilproof.testnet` (publisher as its own controller; the treasury never appears onchain). Score 770 (solid), AI underwriting lend_with_limits, suggested limit 3 NEAR, all 10 checks pass. The old claim `b05bf4684960ee83` stays valid onchain, superseded, never revoked. The audit numbers are unchanged: the v2 claim carries the same predicate public report, so the live-claim line still reads dictionary recovery **no**, exact balance visible **no**, exact score visible **no**.

## Results — AFTER P4 (public report unchanged; disclosure package sealed)

P4 (verifier-bound disclosure, `docs/verifier-bound-disclosure.md`)
seals the disclosure package for one verifier. It does not change the
public report, so the audit numbers are the same as after P3 — the
audit's attacker sees only public data, and P4 leaves the public
report untouched. What P4 changes is the assumption the audit makes
about the disclosure package: before P4 it was a social rule that the
package reaches only the intended verifier; P4 enforces it
cryptographically. Run `npm run audit` to reproduce the table.

| Attack | Result | Chance / baseline | Verdict |
| --- | --- | --- | --- |
| (a) Address recovery (dictionary) | 0/50 recovered | chance 0% | **PASS** |
| (b) Linking via prover commitment | no clusters above chance | chance 1.0% | **PASS** |
| (b) Linking via registry owner field | 100% linked | chance 1.0% | documented limit |
| (c) Balance estimate error (mean) | 94.04% | exact = 0% | **PASS** |
| (c) Score estimate error (mean) | 6.22% | exact = 0% | **PASS** |

## Results — AFTER the v2 registry (commitments, no owner field), 2026-11-06

The v2 contract (`contract/src/lib.rs` 2.0.0, migration in
`docs/contract-migration.md`) removes the last registry-level leak:
`get_claim` returns hashes and salted commitments only, and
`get_owner_claims` is gone. The audit's simulated registry now models
v2 — one shared dedicated publisher account for every claim, each
claim's publisher commitment under its own fresh salt — and the
numbers are from a real run (`npm run audit`, 2026-11-06):

| Attack | Result | Chance / baseline | Verdict |
| --- | --- | --- | --- |
| (a) Address recovery (dictionary) | 0/50 recovered | chance 0% | **PASS** |
| (b) Linking via prover commitment | no clusters above chance | chance 1.0% | **PASS** |
| (b) Linking via registry commitment | no clusters at all (every claim's commitment is unique; 0 predicted pairs) | chance 1.0% | **PASS** |
| (c) Balance estimate error (mean) | 94.04% | exact = 0% | **PASS** |
| (c) Score estimate error (mean) | 6.22% | exact = 0% | **PASS** |
| Live demo claim `2e8675fa662f06a4` | dictionary recovery no, exact balance visible no, exact score visible no | — | **PASS** |

Verdict: **CLEAN**. The registry no longer offers any linking vector
in its public views: with a fresh salt per claim, two claims from the
same publisher (in the simulation, the same dedicated account signs
all 100) carry different commitments, so grouping by commitment
predicts zero pairs. The gate tests in
`test/privacy-audit.test.mjs` assert exactly that (0 predicted pairs,
precision null) plus the residual-correlation note below.

**The deployed registry is still v1 until the migration runs**, so
its owner field is a live leak until then — the v1 rows above are
the current truth for the deployed contract, and this v2 row is the
truth for the code in this repo. Do not quote the v2 row as the live
state until `docs/contract-migration.md` §4 is done.

## Remaining correlation risks (v2 — what the contract cannot fix)

A relayer or a dedicated publisher does **not** make publishing
anonymous. NEAR transaction senders and history are public, and no
contract change alters that. The honest list:

- **Publish transactions name their sender.** Every `publish_claim`
  transaction is signed by the dedicated publisher account, and that
  account, the call time, and the arguments (claim id, hashes,
  commitments — never an address) are visible on the explorer
  forever. Claims published close together from the same publisher
  are trivially grouped by sender and timing. What the grouping
  proves is "the publisher published these claims", never "these
  claims are about this treasury" — the treasury address appears
  nowhere in the transaction. A relayer would only move the sender
  to the relayer's account; the correlation by timing remains.
- **Raw contract state is public.** Anyone can dump it with
  `view_state`. The stored commitments are salted hashes, but the
  salt is stored alongside them (revocation needs it), so a
  dictionary attack CAN recover a predictable controller or
  publisher account id from raw state: hash the dictionary of
  plausible names with each claim's salt and compare. The recovered
  account is a dedicated operational account (publisher or
  controller), never a treasury — that is the boundary the design
  defends, and it is why the controller must never be a treasury
  wallet. Unpredictable (random-subaccount) controller names resist
  the dictionary; readable ones do not — the same lesson as P2's
  prover salts, applied one layer down.
- **The publisher allowlist is public** (`list_publishers`, and the
  admin's `add_publisher`/`remove_publisher` events name the
  account). By design: the publisher is an operational identity, not
  a secret. Key rotation (add new, remove old) is visible too.
- **Migrated legacy claims keep their old owner as controller**
  (via commitment). The old owner is already public from v1 history,
  so this preserves control without adding new exposure — but the
  five legacy claims remain tied, by salted hash, to the demo wallet
  for anyone who dictionary-attacks them. The republished demo claim
  (migration §5) is the one that is clean under the new model.
- **Claim-id squatting is not prevented.** Report ids are 128-bit
  random, so guessing one is infeasible — but anyone who learns a
  report id before it is published can publish it first. The
  squatter's claim is unverifiable against the real report (hash
  mismatch), and the victim's publish fails loudly
  ("claim_id already exists"). Keep report ids private until
  published.
- **What P4 still covers (unchanged):** the disclosure package is
  sealed for one verifier, so the salt — and with it the ability to
  test a controller guess — reaches only the intended verifier
  through the intended channel. The salt is onchain in the claim
  record, so P4 does not hide it; P4 hides the *address* and the
  *snapshot*, which are what the salt would be tested against.

## How to run it

```
npm run audit
```

Deterministic: the same run gives the same table. The live-demo
section reads the committed `public/demo-report.json` (no network).
Note the audit's registry salts are fresh random per run — the table
is deterministic because the attack outcomes do not depend on the
salt values (every claim's commitment is unique whatever the salt),
not because the salts repeat.
