# Balance-sampling evidence — implemented and live

Status: implemented 2026-11-06 (Phase 3) in `src/sampling.js` (mirrored
in `public/js/sampling.js` and the inline copy in `public/verify.html`),
with fetching in `src/onchain.js` and the 10th verifier check in
`src/verify-report.js` (+ mirrors).

## What sampling is — and what it is not

A VeilProof claim about a sustained balance rests on **point-in-time
balance readings** taken at past block heights: the prover's wallet is
read at N evenly spaced heights over a window (the demo: 4 readings
over 1 hour, 900 blocks apart). The lowest of those readings is what
the sustained-balance claim measures.

Sampling **cannot prove continuous possession**. A balance that dips
between two samples and recovers before the next one leaves no trace
in the record. The system says this everywhere it matters, in the same
words:

> Balance samples are point-in-time readings only. They show the
> balance at the sampled blocks; they do not prove the balance was
> held continuously between samples.

The field is always called the **lowest observed sampled balance** —
never "minimum balance", never "continuously held". The limitation
travels in the sampling record itself (`limitation`), in the public
report, and in the verifier's sampling panel.

## The sampling record

`describeSampling(snapshotOrBundle, requested)` returns one record,
used identically by the report, the snapshots and the verifier (one
canonical function, three copies):

```js
{
  windowHours,                    // from the snapshot (null when unknown)
  intervalBlocks,                 // largest gap between complete heights (null with < 2)
  sampleCount,                    // heights present on EVERY wallet
  oldestBlock, newestBlock,       // null with no samples
  sampleTimestamps,               // [{ blockHeight, timestampNs, source }] or null
  timestampSource,                // 'rpc' | 'estimated' | 'unavailable'
  lowestObservedSampledBalance,   // min over complete heights of summed balances (yocto string)
  completeness,                   // 'complete' | 'partial' | 'none'
  missingHeights,                 // sorted heights known missing
  samplesRequested,               // recorded at fetch time (context, not proof)
  wideIntervalWarning,            // null or { reason, intervalBlocks, thresholdBlocks, sampleCount, minSamples, message }
  limitation                      // the honest-language sentence above
}
```

The record is a **derived summary of the pinned samples**, not part of
the report hash: `buildReport` excludes `sampling` (and the score's
derived fields) from the hashed payload, and the verifier's `sampling`
check recomputes the record from the disclosure snapshots and compares
it field by field. A report that misstates its sampling fails the
check; a report that claims no sampling evidence passes vacuously
when the disclosure carries no samples.

### Completeness

- `complete` — every requested reading is present (and no height is
  missing from the grid).
- `partial` — some reading is missing. Missing heights come from three
  independent signals: heights the fetch recorded as unservable,
  heights present on some wallets but not all, and heights implied by
  the grid (when gaps are exact multiples of the smallest gap, the
  in-between heights are missing). A height present on some wallets
  but not all is missing, and is **excluded from the sums** — a sum
  over a missed height would understate the balance.
- `none` — no samples at all.

`samplesRequested` is context recorded at fetch time, not proof: the
grid check is the independent signal, so a prover cannot claim
completeness by understating what was requested.

### Timestamps

A sample's time comes from the block header when the chain served it
(`source: 'rpc'`). When the header was unavailable, the time is
**estimated** from the newest disclosed transaction's block height and
timestamp, at 1 second per block (`source: 'estimated'`). With no
stored timestamp and no transaction anchor, times are `null` and the
source is `'unavailable'`.

The 1 s/block estimate is a labelled estimate, not a measurement: real
testnet spacing is ~0.62 s/block (the demo's four heights span
~549–559 s per 900 blocks), so an estimate would be off by hours over
a long window. That is why the demo's committed timestamps are the
real ones, read from the chain via RPC — never estimated, never
guessed.

### The wide-interval warning

A warning is raised when the evidence is too thin to call a balance
sustained:

- interval over **3600 blocks** (about 1 hour at ~1 block/sec), or
- fewer than **4 samples** over the window.

`reason` is `interval_too_wide`, `too_few_samples`, or `both`, with a
human-readable `message`. The warning is surfaced in the report and in
the verifier's sampling panel — and it is **never a failure**: thin
evidence is not false evidence, so the sampling check passes with the
warning in its detail.

## Fetching: hard failures become completeness flags

`sampleBalanceHistoryDetailed` (`src/onchain.js`) reads one height at
a time. A height the node cannot serve (account younger than the
window, pruned height, node hiccup) is recorded in `missingHeights`
and the readings that did come back are kept — the report can still be
produced honestly, with the gap visible in the record. A hard failure
remains only when **nothing** could be read (zero samples), because
then there is no evidence at all.

The block timestamp is fetched best-effort per height; when the header
is unavailable the balance reading stands and the timestamp is
estimated instead (see above).

## Where the record lives

- **Disclosure snapshot** — each snapshot carries its own `sampling`
  record (per-wallet), plus `balanceSamples` (now with optional
  `blockTimestampNs`) and `balanceSampleWindowHours`.
- **Public report** — the bundle-level `sampling` record. It is the
  one place the public report carries an exact value on purpose: the
  `lowestObservedSampledBalance` (the sustained threshold is already
  public, and the sampling evidence is meaningless without its
  observed minimum). Exact claim values and score points stay
  stripped.
- **Verifier UI** — `buildStatusPanelsHtml` renders the sampling panel
  (count, interval, oldest/newest block, lowest observed sampled
  balance, completeness with missing heights, sample times, warning)
  and the demo page's facts show the same summary.

## Worked numbers (the live demo claim)

Demo claim `b05bf4684960ee83`: 4 readings, heights 276512600 /
276513500 / 276514400 / 276515300 (step 900 blocks, window 1 h),
timestamps `rpc`, completeness `complete`, no warning, lowest
observed sampled balance 12.6479960579369012 NEAR (primary ~11.148 +
linked ~1.5 at every height). See `scripts/refresh-demo-phase3.mjs`
for how the committed demo files gained the Phase 3 fields with the
onchain-pinned report hash unchanged.

## Honest limits

- Sampling proves the balance **at the sampled blocks only**. A dip
  that starts and ends between two samples is invisible, and the
  record says so.
- The wide-interval thresholds (3600 blocks, 4 samples) are a
  judgement call about what counts as "too thin", documented here and
  in the code — not a property of the chain.
- Estimated timestamps are labelled estimates. A verifier that needs
  exact times should require `timestampSource: 'rpc'`.
- Completeness is only as good as the grid: a prover who samples
  rarely and evenly leaves no grid gap to detect, which is exactly
  what the wide-interval warning is for.
