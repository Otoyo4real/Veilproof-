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

## Results — AFTER (to be filled when P2/P3 land)

| Attack | Result | Chance / baseline | Verdict |
| --- | --- | --- | --- |
| (a) Address recovery (dictionary) | _pending_ | — | _pending_ |
| (b) Linking via prover commitment | _pending_ | chance 1.0% | _pending_ |
| (b) Linking via registry owner field | _pending_ | chance 1.0% | documented limit |
| (c) Balance estimate error (mean) | _pending_ | exact = 0% | _pending_ |
| (c) Score estimate error (mean) | _pending_ | exact = 0% | _pending_ |

## How to run it

```
npm run audit
```

Deterministic: the same run gives the same table. The live-demo
section reads the committed `public/demo-report.json` (no network).
