# score-v2 — implemented and live

Status: implemented 2026-11-06 in `src/score.js` (mirrored in
`public/js/score.js` and the inline copy in `public/verify.html`),
after Isaiah asked to implement all five VeilProof improvements and
said the agent-privacy use case alone is not strong enough to win.
`computeScore` defaults to score-v2 and takes an explicit version
parameter; the verifier recomputes a report under its own declared
version, so v1 reports keep verifying as v1 — shipping v2 never
breaks v1. The first v2 demo claim is published separately (see
below); the v1 demo claim 7c063555730c20fb stays valid, never revoked.

## The gaming hole in v1

v1 counts every successful transaction and every unit of volume the same,
including transfers between the prover's own wallets. A prover holding 12 NEAR
can wash it between two of their own wallets for an afternoon and score:

- sustained 300 + time-weighted 200 + activity 170 (30+ txs, one week, no
  spread bonus) + volume 150 (≥10 NEAR washed) + no_failed 100 + staked 0
  = **920/1000 (strong)** — for a history with zero outside counterparties.

The sustained-balance component is the only part that costs real capital, and
it is the only part wash trading cannot fake. v2 makes that the centre of the
score and stops rewarding self-dealing.

## What changes in v2 (total still 1000)

| Component | v1 max | v2 max | Change |
| --- | --- | --- | --- |
| sustained_balance | 300 | **350** | Same tiers, points 60 / 140 / 230 / 300 / 350 at 0.1 / 0.5 / 1 / 5 / 10 NEAR |
| time_weighted_balance | 200 | **150** | Same tiers, points 30 / 60 / 100 / 130 / 150 |
| activity | 200 | **150** | Counts **external txs only** (at least one endpoint outside the bundle). Tiers: 1–2: 30, 3–9: 70, 10–29: 105, ≥30: 130; +20 spread bonus (≥3 distinct weeks), capped at 150 |
| volume | 150 | **100** | Counts **external volume only**. Tiers: 0.1: 20, 0.5: 40, 1: 70, 5: 90, ≥10: 100 |
| counterparty_diversity (NEW) | — | **100** | Distinct outside counterparties in the tx window (an account that is neither the primary nor a linked wallet, on either side of an external tx). Tiers: 0: 0, 1: 30, 2–3: 60, 4–9: 85, ≥10: 100 |
| no_failed | 100 | 100 | Unchanged |
| staked | 50 | 50 | Unchanged |

Definitions, to keep the score recomputable by any verifier:

- **External tx:** a union tx where `senderId` or `receiverId` is not in the
  bundle's wallet set. A transfer between two of the prover's own wallets is
  internal and earns nothing in activity, volume or diversity.
- **Outside counterparty:** a distinct accountId appearing on the other side
  of an external tx. Counted once per account, not per tx.
- **Windows:** same inclusive window rule as v1
  (`nowNs - days * 86400e9 <= blockTimestampNs <= nowNs`).
- **Measured flags:** diversity is measured only when `txWindowDays` is
  supplied (it needs the same window); unmeasured components score 0 and are
  marked `measured: false`, as in v1.

## Worked numbers (verified from the public demo files)

Demo claim `7c063555730c20fb` (bundle: `veilproof-demo.testnet` +
`demo2.veilproof.testnet`; 5 txs, 4 of them with `veilproof.testnet` on the
other side, 1 internal link transfer):

- v1: 300 + 200 + 90 + 100 + 100 + 0 = **790 (solid)** — as published.
- v2: sustained 350 (≥10 NEAR) + time-weighted 150 (≥10) + activity 70
  (4 external txs) + volume 70 (1.85 NEAR external) + diversity 30
  (1 outside counterparty) + no_failed 100 + staked 0 = **770 (solid)**.

An honest treasury barely moves (790 → 770) because its money is real and
held. The wash attack above collapses: v2 gives it sustained 350 +
time-weighted 150 + activity 0 + volume 0 + diversity 0 + no_failed 100 +
staked 0 = **600** — the bottom edge of solid, down 320 points from 920.

## Predicate disclosure (P3) — live 2026-11-06

The score is computed exactly as above, but the **public report no longer carries the exact value or the per-component points**. It carries:

- `version` (`score-v2`), `band` (`thin` / `building` / `solid` / `strong`), and the component shapes (`id`, `label`, `max`, `measured`) — no `value`, no `points`.

The exact value and points live only in the private disclosure package (the verifier recomputes them from the snapshots). The verifier checks the recomputed exact score falls in the public band and the components match on `id`/`label`/`max`/`measured`; a tampered band fails. The check detail prints the band, never the number.

Pre-P3 reports carry the exact value and points and still verify (legacy path: exact match). `buildReport` strips exact values by default; `includeExactValues: true` is the legacy opt-in for tests only — never for a new publish. The tripwire (`assertPublicReportClean`) refuses any report that carries an exact value or points.

Same for claims (see `docs/privacy-audit.md`): the public report carries `{ id, passed, threshold }` only. The verifier checks the recomputed claim's `passed` and `threshold` match, and for legacy reports the exact `value` too.

## Phase 3: manipulation detection (live 2026-11-06)

v2 stopped *rewarding* self-dealing; Phase 3 *flags* it. The detectors run
in `src/manipulation.js` (mirrored in `public/js/manipulation.js` and the
inline copy in `public/verify.html`) on the same windowed, successful,
union-deduped txs the score uses. They are deterministic — integer math,
BigInt yocto, no floats, no AI, no offchain data — so any verifier
recomputes the same flags from the same snapshots. The verifier compares
them against the report's public score fields (see below).

### Risk flags

`score.riskFlags` is an array of `{ type, detail, severity }`, sorted by
`(type, detail)`. Flag details carry counts and NEAR amounts only, never
account ids, so they are safe to publish in the public report.

| Type | Rule (all thresholds in `src/manipulation.js`) | Severity |
| --- | --- | --- |
| `circular_flow` | With one outside counterparty, the smaller of the two directions is ≥ 0.1 NEAR **and** at least 50% of the larger direction came back within the window. | medium; high when ≥ 1 NEAR returned or ≥ 90% returned |
| `circular_chain` | Funds left a bundle wallet and returned through a simple cycle of 3–4 hops including a bundle wallet, every leg ≥ 0.1 NEAR. 2-cycles are `circular_flow`'s job, not this one. At most 3 cycles reported, largest minimum leg first. Enumeration is skipped entirely when the graph is large (> 64 nodes or > 256 edges) — a guard, not a silent pass: the other detectors still run. | medium; high when the smallest leg is ≥ 1 NEAR |
| `shared_funder` | One outside account sent funds to ≥ 2 distinct wallets in the bundle. | medium |
| `concentrated_counterparty` | One outside account is on ≥ 80% of external txs (min 2 external txs). | medium |
| `repeated_transfers` | The same ordered pair moved the same exact amount ≥ 3 times in the window. At most 3 groups reported, most frequent first. | medium; high at ≥ 5 repeats or ≥ 10 NEAR total |
| `internal_transfers` | Any transfer between the bundle's own wallets in the window. Informational: internal transfers earn nothing, and the flag says so. | low |

Detection runs only when `txWindowDays` is supplied (the score is only
assessed then). Without a window, `riskFlags` and `counterpartyLabels`
are empty — not guessed. Failed txs and txs outside the window never
trigger a flag. Duplicate tx hashes listed in more than one snapshot
collapse to one in the union, so a transfer listed twice is not a
phantom repeat.

### Counterparty labels

`score.counterpartyLabels` is `[{ account, label }]` for every account
on a windowed bundle tx, sorted by account:

- `own` — one of the prover's own wallets (primary or linked).
- `suspicious` — an outside account that appears in a medium or high
  risk flag.
- `unknown` — every other outside account. **Unknown is the default.**
  No source in this system identifies who runs an account, so
  independence is never assumed: an outside counterparty is labelled
  `unknown` unless a flag marks it `suspicious`, and `unknown` never
  means "verified independent".

Labels name account ids, so they **never** travel in the public report.
The report carries only `counterpartySummary` (`{ own, unknown,
suspicious }` counts), and the tripwire (`assertPublicReportClean`)
refuses a report that contains a counterparty account id. The verifier
recomputes the labels from the disclosure and compares the summary.

### The disclaimer

Every score carries this disclaimer, in the score output itself:

> This score measures observable onchain financial activity only. It is
> not a guarantee of repayment, identity, beneficial ownership, or
> creditworthiness.

### Flag-only diversity (the rule, stated deterministically)

Flags **do not change points**. Diversity still counts every distinct
outside counterparty, including one a flag marks suspicious — the flag
is a warning attached to the points, not a discount of them. The demo
is the proof: its single outside counterparty is flagged
`concentrated_counterparty`, and its diversity still scores 30 points
for that one counterparty, exactly as the v2 tiers say. A future
score-v3 may discount diversity from flagged counterparties; v2 does
not, because discounting would change published scores (the demo would
drop from 770 to 740). The verifier enforces the rule by comparing the
report's flags, summary and disclaimer against its own recompute — a
report that hides a flag fails the score check.

The public report carries `riskFlags`, `counterpartySummary` and
`disclaimer` in both the predicate and the legacy exact forms (they are
compared only when present, so pre-Phase-3 reports still verify). The
score `value`, `band` and components stay hashed; the derived fields
are excluded from the report hash and checked by recomputation instead
(see `docs/sampling.md` for the same treatment of the sampling record).

### What Phase 3 cannot detect

A true identity/ownership (sock-puppet) check is **not implemented**,
because no onchain data proves who runs an account. What exists instead
is the observable proxy: every outside counterparty is `unknown` by
default, and the shared-funder, circular-flow, circular-chain,
concentration and repeated-transfer flags catch the *patterns* a
sock-puppet ring leaves onchain. A ring that transacts like genuinely
independent counterparties — distinct funding, no round trips, spread
activity — is indistinguishable from the real thing by any onchain-only
method, and this system says so rather than claiming otherwise.

## Honest limits (say these in the submission, do not hide them)

- Diversity counts distinct accounts, and a determined prover can create
  sock-puppet accounts. Phase 3 flags the patterns puppets leave
  (shared funder, round trips, concentration, repeats) and labels every
  outside counterparty `unknown` by default — but a puppet ring that
  mimics independent activity is indistinguishable onchain, and no
  identity check exists to catch it. Diversity is a friction with
  warnings attached, not a proof of independence.
- The demo's single outside counterparty (`veilproof.testnet`) is the account
  that funded the demo history, so even the demo's 30 diversity points are
  generous — and the demo now says so in its own public report, as a
  `concentrated_counterparty` risk flag. A richer demo treasury with genuinely independent counterparties
  would show the component better; the current demo cannot, and that should
  be stated, not papered over.
- v2 is calibrated for testnet-scale treasuries, like v1. Mainnet-scale
  recalibration is a later version, not this one.

## Implementation checklist — DONE 2026-11-06

1. `src/score.js`: counterparty_diversity added, external-only filtering for activity/volume, new weights; `SCORE_VERSION` is `score-v2` for newly computed scores, v1 code path kept so old reports verify. ✅
2. `docs/score-v1.md`: left untouched as the v1 recipe. ✅
3. `src/verify-report.js` + browser mirror + verify.html inline: recompute the declared version. ✅
4. `test/score.test.mjs`: v2 demo case (770), wash case (600), v1 still 790. ✅ (full suite 125/125)
5. Demo claim re-published under v2 and re-verified live: report `a41d9faaa0a19148`, publish tx `3za51UYQNxrkZQT54ZPyTS8BHwRLKbCMFhZwXHuUFNoE`, score 770 (solid), all 9 checks pass; landing copy updated after the live check passed. ✅ — superseded by the salted + predicate republish `b05bf4684960ee83` (publish tx `3ouNst9DcYkcptEpua7EzqdLDmuY8P8uFsKRgU9TW9PQ`), which is the live demo claim; its Phase 3 refresh (sampling record + risk flags, report hash unchanged) re-verified live with all 10 checks passing. ✅
6. AI underwriting prompt/guard unchanged — band edges did not move (thin <300, building 300–599, solid 600–799, strong ≥800). ✅

## Phase 3 checklist — DONE 2026-11-06

1. `src/manipulation.js`: the six detectors above, `labelCounterparties`, `counterpartySummary`, `SCORE_DISCLAIMER`; mirrored in `public/js/manipulation.js` and the inline copy in `public/verify.html`. ✅
2. `src/score.js`: `computeScore` returns `riskFlags`, `counterpartyLabels`, `counterpartySummary`, `disclaimer` (v1 and v2 alike; points unchanged). ✅
3. `src/report.js` + `src/disclosure.js`: public score carries the flags, summary and disclaimer (never labels); tripwire checks counterparty ids as extra secrets. ✅
4. `src/verify-report.js` + browser mirror + verify.html inline: the score check compares flags/summary/disclaimer when the report carries them; `deriveScoreLimits` merges manipulation flags with component flags; counterparty labels come from the recomputed score. ✅
5. `test/score-manipulation.test.mjs`: 17 tests against the real engine — circular flow and chain, shared funder, concentration and repeat boundaries, duplicate-hash dedup, internal transfers earning nothing, UNKNOWN labelling, the disclaimer, and the flag-only rule (flagged vs clean bundles score identically). ✅
6. Demo claim `b05bf4684960ee83` refreshed (see `scripts/refresh-demo-phase3.mjs`): 2 risk flags (`concentrated_counterparty` medium, `internal_transfers` low), summary `{ own: 2, unknown: 0, suspicious: 1 }`, score still 770 solid, report hash unchanged and re-verified live against the registry. ✅
