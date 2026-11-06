# score-v1 — the VeilProof portable credit score (published rules)

This document is the shared recipe. Any app holding a disclosure package can recompute a score-v1 score from the same snapshots and the same windows and get the exact same number — that is what makes the score reusable across apps. The verifier re-runs it on every check (see `src/verify-report.js`); a reported score that differs from the recomputed one fails verification.

## Inputs

- A snapshot bundle: one or more wallet snapshots, each `{ account: { accountId, amount, locked }, txs: [...], balanceSamples?: [...] }`.
- Windows (in days, all optional): `txWindowDays`, `volumeWindowDays`, `noFailedWindowDays`.
- `nowNs`: the nanosecond epoch the windows are measured against. The score is computed at report-build time and recomputed at verify time with the report's `nowNs` — windows are relative, so the same windows and the same snapshots always give the same score.

## Components (total 1000)

All amounts are compared as yocto BigInts (1 NEAR = 10^24 yocto). A component the prover did not measure scores 0 and is marked `measured: false` — the score never hides what it did not see.

### sustained_balance — max 300

The lowest sampled balance across the sampled window, summed across wallets per sample point (sample points aligned by block height). Tiers (NEAR → points):

| Lowest sampled balance | Points |
| --- | --- |
| < 0.1 | 0 |
| 0.1 – 0.49 | 50 |
| 0.5 – 0.99 | 120 |
| 1 – 4.99 | 200 |
| 5 – 9.99 | 260 |
| >= 10 | 300 |

Measured only when every wallet carries non-empty `balanceSamples`. This is the anti-flash component: a deposit made an hour before the report does not raise it.

### time_weighted_balance — max 200

The mean sampled balance across the sampled window (integer mean of the per-point sums, yocto). Tiers:

| Mean sampled balance | Points |
| --- | --- |
| < 0.1 | 0 |
| 0.1 – 0.49 | 40 |
| 0.5 – 0.99 | 80 |
| 1 – 4.99 | 130 |
| 5 – 9.99 | 170 |
| >= 10 | 200 |

Measured only when samples exist (same condition as sustained_balance).

### activity — max 200

Successful transactions in the tx window, counted once per transaction hash across all wallets. Base points by count, plus a spread bonus:

| Success tx count | Base points |
| --- | --- |
| 0 | 0 |
| 1 – 2 | 40 |
| 3 – 9 | 90 |
| 10 – 29 | 140 |
| >= 30 | 170 |

Spread bonus: +30 (capped at 200 total) when the successful transactions span at least 3 distinct ISO calendar weeks inside the window. Spread beats a burst: one afternoon of wash transactions cannot max this component out.

Measured only when `txWindowDays` is supplied.

### volume — max 150

Summed volume in the volume window, each transaction counted once across all wallets, only when the transaction touches at least one of the bundle's wallets. Tiers:

| Volume | Points |
| --- | --- |
| < 0.1 | 0 |
| 0.1 – 0.49 | 30 |
| 0.5 – 0.99 | 60 |
| 1 – 4.99 | 100 |
| 5 – 9.99 | 130 |
| >= 10 | 150 |

Measured only when `volumeWindowDays` is supplied.

### no_failed — max 100

100 when zero failed transactions fall inside the no-failed window, 0 otherwise. Measured only when `noFailedWindowDays` is supplied.

### staked — max 50

50 when the summed staked (locked) balance across wallets is greater than zero, else 0. Always measured — it needs only the account states.

## Bands

| Score | Band |
| --- | --- |
| 0 – 299 | thin |
| 300 – 599 | building |
| 600 – 799 | solid |
| 800 – 1000 | strong |

A band is a label, not a lending decision. The AI underwriter (`src/ai-analysis.js`, `analyseUnderwriting`) gives the advisory verdict, and a deterministic guard turns any 'lend' on a thin score (< 300) into a 'decline'.

## Calibration and versioning

score-v1 is calibrated for testnet-scale treasuries (a ~10 NEAR wallet with clean, spread-out history scores in the solid band). A mainnet-scale recalibration would ship as score-v2 with larger tier thresholds; the `version` field exists so v1 and v2 scores are never confused, and the verifier only ever recomputes the version the report declares.

## Recomputation recipe (for implementers)

1. Take the disclosure package's snapshots (primary + linked).
2. Take the policy's windows (`txWindowDays`, `volumeWindowDays`, `noFailedWindowDays`).
3. Run `computeScore({ wallets: snapshots }, windows, nowNs)` — or reimplement the tiers above exactly, with yocto BigInt comparisons and the same window rule (both window edges inclusive: `nowNs - days * 86400e9 <= blockTimestampNs <= nowNs`).
4. Compare `version`, `value`, `band` and the full `components` array (id, label, points, max, measured) with the report's `score`. Any difference means the score was tampered with.
