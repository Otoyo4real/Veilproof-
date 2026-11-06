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

## Honest limits (say these in the submission, do not hide them)

- Diversity counts distinct accounts, and a determined prover can create
  sock-puppet accounts. Each puppet costs a real transfer and real history,
  and the score still cannot be maxed without sustained capital — but
  diversity is a friction, not a proof of independence.
- The demo's single outside counterparty (`veilproof.testnet`) is the account
  that funded the demo history, so even the demo's 30 diversity points are
  generous. A richer demo treasury with genuinely independent counterparties
  would show the component better; the current demo cannot, and that should
  be stated, not papered over.
- v2 is calibrated for testnet-scale treasuries, like v1. Mainnet-scale
  recalibration is a later version, not this one.

## Implementation checklist (for the main agent, not done here)

1. `src/score.js`: add `counterparty_diversity`, external-only filtering for
   activity/volume, new weights; bump `SCORE_VERSION` to `score-v2` only for
   newly computed scores — keep a v1 code path so old reports verify.
2. `docs/score-v1.md`: leave untouched as the v1 recipe.
3. `src/verify-report.js` + browser mirror: recompute the declared version.
4. `test/score.test.mjs`: v2 demo case (770), wash case (600), v1 still 790.
5. Re-publish the demo claim under v2 and re-verify live; update the landing
   copy's score line only after the live check passes.
6. Update the AI underwriting prompt/guard only if the band edges move — they
   do not (thin <300, building 300–599, solid 600–799, strong ≥800).
