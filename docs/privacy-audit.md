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

## How to run it

```
npm run audit
```

Deterministic: the same run gives the same table. The live-demo
section reads the committed `public/demo-report.json` (no network).
