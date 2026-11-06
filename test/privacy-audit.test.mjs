// VeilProof privacy audit tests — the audit's assertions, as tests.
//
// These assert the DESIRED properties: 0 address recoveries, linking
// no better than chance, and balance/score estimates that are bounds,
// not exact values. They FAIL while the leaks exist (P1's "before"
// measurement) and PASS once P2 (salts), P3 (predicates) and the v2
// registry (commitments, no owner field) fix them. A failing test
// here is a finding, not a broken feature — see docs/privacy-audit.md
// for the before/after table.
//
// The registry-linking test changed with v2: there is no owner field
// any more, so the test asserts the audit's registry attack finds NO
// linkable groups at all (per-claim salted publisher commitments
// yield singletons) and that the audit still reports the residual
// offchain correlation (public transaction history) in its note,
// so the limit can never be silently dropped.
import test from 'node:test';
import assert from 'node:assert/strict';
import { runAudit } from '../scripts/privacy-audit.mjs';

test('audit: zero address recoveries across all 50 simulated provers', () => {
  const r = runAudit();
  assert.equal(
    r.addressRecovery.recovered,
    0,
    `attacker recovered ${r.addressRecovery.recovered}/${r.addressRecovery.of} addresses ` +
      `(${r.addressRecovery.dictionaryRecovered}/${r.addressRecovery.dictionaryOf} dictionary-named, ` +
      `${r.addressRecovery.randomRecovered}/${r.addressRecovery.randomOf} random)`,
  );
});

test('audit: linking via prover commitment is no better than chance', () => {
  const r = runAudit();
  const l = r.linkingByCommitment;
  assert.ok(
    l.precision === null || l.precision <= l.chance,
    `linking precision ${(l.precision * 100).toFixed(1)}% beats chance ${(l.chance * 100).toFixed(1)}% ` +
      `(${l.truePairs}/${l.predictedPairs} predicted pairs correct)`,
  );
});

test('audit: balance and score estimates from the public report are bounds, not exact values', () => {
  const r = runAudit();
  assert.ok(
    r.balanceEstimation.meanAbsPctError >= 1,
    `balance estimate error ${r.balanceEstimation.meanAbsPctError.toFixed(2)}% — the exact balance is readable from the public report`,
  );
  assert.ok(
    r.scoreEstimation.meanAbsPctError >= 1,
    `score estimate error ${r.scoreEstimation.meanAbsPctError.toFixed(2)}% — the exact score is readable from the public report`,
  );
});

test('audit: the registry offers no linking vector (v2 commitments are per-claim salted)', () => {
  const r = runAudit();
  assert.equal(
    r.linkingByRegistry.predictedPairs,
    0,
    `registry attack predicted ${r.linkingByRegistry.predictedPairs} same-publisher pairs — commitments must be unlinkable`,
  );
  assert.equal(
    r.linkingByRegistry.precision,
    null,
    'registry linking precision must be null (no groups at all), not a number',
  );
  assert.ok(
    typeof r.linkingByRegistry.note === 'string' && r.linkingByRegistry.note.length > 0,
    'audit must carry the residual-correlation note for the registry (public tx history)',
  );
  assert.match(
    r.linkingByRegistry.note,
    /transaction/,
    'the residual-correlation note must name public transaction history as the remaining vector',
  );
});
