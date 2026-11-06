// One-time refresh of the committed demo files for Phase 3.
//
//   node scripts/refresh-demo-phase3.mjs
//
// Adds to the committed demo claim b05bf4684960ee83, without touching
// any onchain record and without any key or wallet:
//
//   - real block timestamps (read from the chain via RPC at refresh
//     time, recorded below) on every balance sample in both snapshots;
//   - a per-snapshot sampling record on each snapshot;
//   - the bundle-level sampling record and the public score fields
//     (riskFlags, counterpartySummary, disclaimer) on the report.
//
// The onchain-pinned report hash MUST NOT change: the new fields are
// excluded from the report hash (they are deterministic functions of
// the data-hash-pinned snapshots, and the verifier recomputes them),
// and the timestamps/sampling do not change the data hash. This
// script asserts all of that before writing anything, and refuses to
// write if the demo score is no longer 770 solid — the demo
// transactions age out of their 30-day windows, so this refresh is
// only meaningful while the demo is fresh (November 2026). Do NOT
// re-run it after the windows have passed; it will refuse, by design.

import fs from 'node:fs';
import { describeSampling } from '../src/sampling.js';
import { computeScore } from '../src/score.js';
import { reportHash, evidenceHash } from '../src/report.js';
import { dataHashForSnapshots, computeMultiDataHash } from '../src/onchain.js';

// Real block timestamps, read live from rpc.testnet.near.org on
// 2026-11-06 for the four demo sample heights. Never guessed: the
// spacing is ~549-559 s per 900 blocks (~0.62 s/block), so a 1 s/block
// estimate would be off by hours.
const BLOCK_TIMESTAMPS_NS = {
  276512600: '1793984070060846322',
  276513500: '1793984629083706482',
  276514400: '1793985178704100861',
  276515300: '1793985730538890117',
};

const root = new URL('..', import.meta.url);
const read = (p) => JSON.parse(fs.readFileSync(new URL(p, root), 'utf8'));
const write = (p, obj) => fs.writeFileSync(new URL(p, root), `${JSON.stringify(obj, null, 2)}\n`);

const oldReport = read('public/demo-report.json');
const disclosure = read('public/demo-disclosure.json');
const policy = read('public/demo-policy.json');

if (oldReport.reportId !== 'b05bf4684960ee83') {
  throw new Error(`refresh: expected demo claim b05bf4684960ee83, found ${oldReport.reportId}`);
}
if (oldReport.sampling !== undefined) {
  throw new Error('refresh: demo report already carries sampling — refusing to run twice');
}

const oldReportHash = reportHash(oldReport);
const oldEvidenceHash = evidenceHash(oldReport.evidenceRefs);
// The verifier's data hash is the MULTI hash over all snapshots,
// pinned in report.evidenceRefs.dataHash — NOT disclosure.dataHash,
// which is the primary snapshot's own single-wallet hash (duplicated
// at the top level by buildDisclosurePackage). Each snapshot also
// carries its own single-wallet hash in snapshot.dataHash.
const oldMultiHash = oldReport.evidenceRefs.dataHash;
const oldSnapshotDataHash = disclosure.snapshot.dataHash;
const oldLinkedDataHash = disclosure.linked[0].snapshot.dataHash;

const snapshots = [disclosure.snapshot, ...disclosure.linked.map((l) => l.snapshot)];

// 1. Real block timestamps on every balance sample.
for (const snap of snapshots) {
  for (const sample of snap.balanceSamples) {
    const ts = BLOCK_TIMESTAMPS_NS[sample.blockHeight];
    if (!ts) {
      throw new Error(`refresh: no real block timestamp for height ${sample.blockHeight} — fetch it from RPC, do not guess`);
    }
    sample.blockTimestampNs = ts;
  }
}

// 2. Per-snapshot sampling records (4 requested, none missing).
for (const snap of snapshots) {
  snap.sampling = describeSampling(snap, { samplesRequested: 4, missingHeights: [] });
}

// 3. Bundle sampling + the score the verifier will recompute.
const bundleSampling = describeSampling({ wallets: snapshots });
const nowNs = (BigInt(Date.now()) * 1000000n).toString();
const score = computeScore(
  { wallets: snapshots },
  {
    txWindowDays: policy.txWindowDays,
    volumeWindowDays: policy.volumeWindowDays,
    noFailedWindowDays: policy.noFailedWindowDays,
  },
  nowNs,
  oldReport.score.version,
);
if (score.value !== 770 || score.band !== 'solid') {
  throw new Error(`refresh: demo score is no longer 770 solid (got ${score.value} ${score.band}) — the demo windows have aged out, refusing to rewrite`);
}

// 4. The refreshed report: every old field byte-identical in place,
// the public score fields after components (buildReport's order),
// sampling last (buildReport's order).
const newReport = {
  ...oldReport,
  score: {
    ...oldReport.score,
    riskFlags: score.riskFlags,
    counterpartySummary: score.counterpartySummary,
    disclaimer: score.disclaimer,
  },
  sampling: bundleSampling,
};

// 5. Proofs before writing anything.
if (reportHash(newReport) !== oldReportHash) {
  throw new Error('refresh: report hash changed — the hash exclusion is broken, refusing to write');
}
if (evidenceHash(newReport.evidenceRefs) !== oldEvidenceHash) {
  throw new Error('refresh: evidence hash changed — refusing to write');
}
const newMultiHash = await dataHashForSnapshots(snapshots);
if (newMultiHash !== oldMultiHash) {
  throw new Error(`refresh: multi data hash changed (${oldMultiHash} -> ${newMultiHash}) — refusing to write`);
}
if (computeMultiDataHash([disclosure.snapshot]) !== oldSnapshotDataHash) {
  throw new Error('refresh: primary snapshot data hash changed — refusing to write');
}
if (computeMultiDataHash([disclosure.linked[0].snapshot]) !== oldLinkedDataHash) {
  throw new Error('refresh: linked snapshot data hash changed — refusing to write');
}
if (JSON.stringify(newReport.claims) !== JSON.stringify(oldReport.claims)) {
  throw new Error('refresh: claims changed — refusing to write');
}

write('public/demo-report.json', newReport);
write('public/demo-disclosure.json', disclosure);

console.log('refresh-demo-phase3: demo files refreshed');
console.log(`  reportId ${newReport.reportId} — report hash unchanged: ${oldReportHash.slice(0, 16)}…`);
console.log(`  data hash unchanged: ${oldMultiHash.slice(0, 16)}… (multi, pinned in evidenceRefs)`);
console.log(`  sampling: ${bundleSampling.sampleCount} readings, interval ${bundleSampling.intervalBlocks} blocks, completeness ${bundleSampling.completeness}, timestamps ${bundleSampling.timestampSource}, lowest observed sampled balance ${bundleSampling.lowestObservedSampledBalance} yocto`);
console.log(`  score: ${score.value} (${score.band}), ${score.riskFlags.length} risk flag(s): ${score.riskFlags.map((f) => `${f.type}/${f.severity}`).join(', ')}`);
console.log(`  counterparties: ${JSON.stringify(score.counterpartySummary)}`);
console.log('  next: npm run demo (all 10 checks must pass) + the live registry hash check');
