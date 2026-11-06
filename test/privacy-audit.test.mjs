// VeilProof privacy audit tests — the audit's assertions, as tests.
//
// These assert the DESIRED properties: 0 address recoveries, linking
// no better than chance, and balance/score estimates that are bounds,
// not exact values. They FAIL while the leaks exist (P1's "before"
// measurement) and PASS once P2 (salts) and P3 (predicates) fix them.
// A failing test here is a finding, not a broken feature — see
// docs/privacy-audit.md for the before/after table.
//
// The registry-owner linking test is different: the owner field is
// public by design (revocation needs an owner), so salts cannot fix
// it. That test asserts the audit MEASURES and REPORTS it, so the
// limit can never be silently dropped.
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

test('audit: the registry-owner linking limit is measured and reported, never hidden', () => {
  const r = runAudit();
  assert.ok(
    typeof r.linkingByOwner.precision === 'number',
    'audit must report the owner-field linking precision',
  );
  assert.ok(
    typeof r.linkingByOwner.note === 'string' && r.linkingByOwner.note.length > 0,
    'audit must carry the documented-limit note for owner-field linking',
  );
});
