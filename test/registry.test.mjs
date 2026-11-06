// VeilProof registry v2 helpers — cross-implementation checks.
//
// The golden vectors below are the contract's own outputs: the Rust
// unit tests emit publisher_commitment
// 99695b4d7c81cc28405549d2f23381c0401359f84bd92719819919dbbc105d6d for
// salt 64x'1' and publisher.veilproof.testnet, and node:crypto must
// produce the identical bytes. If the formula drifts in either place,
// these tests fail — that is the point.
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  commitmentHex,
  newCommitmentSalt,
  buildPublishCommitments,
  buildV2PublishArgs,
  isV2Version,
  probeContractVersion,
  PUBLISHER_COMMITMENT_DOMAIN,
  CONTROLLER_COMMITMENT_DOMAIN,
} from '../src/registry.js';

const SALT = '1'.repeat(64);
const PUBLISHER = 'publisher.veilproof.testnet';
const CONTROLLER = 'controller.veilproof.testnet';

test('registry: publisher commitment matches the contract output', () => {
  assert.equal(
    commitmentHex(PUBLISHER_COMMITMENT_DOMAIN, SALT, PUBLISHER),
    '99695b4d7c81cc28405549d2f23381c0401359f84bd92719819919dbbc105d6d',
  );
});

test('registry: controller commitment matches the contract formula', () => {
  assert.equal(
    commitmentHex(CONTROLLER_COMMITMENT_DOMAIN, SALT, CONTROLLER),
    'b1a2adc1632e550f2e078e3e735424d4b4cc380afd996d46e496e2546e901508',
  );
});

test('registry: domains separate publisher from controller commitments', () => {
  const pub = commitmentHex(PUBLISHER_COMMITMENT_DOMAIN, SALT, PUBLISHER);
  const ctrl = commitmentHex(CONTROLLER_COMMITMENT_DOMAIN, SALT, PUBLISHER);
  assert.notEqual(pub, ctrl, 'same account and salt must not collide across roles');
});

test('registry: fresh salts give unlinkable commitments', () => {
  const a = buildPublishCommitments({ publisherAccountId: PUBLISHER, controllerAccountId: CONTROLLER });
  const b = buildPublishCommitments({ publisherAccountId: PUBLISHER, controllerAccountId: CONTROLLER });
  assert.notEqual(a.commitment_salt, b.commitment_salt);
  assert.notEqual(a.publisher_commitment, b.publisher_commitment);
  assert.notEqual(a.controller_commitment, b.controller_commitment);
  assert.match(a.commitment_salt, /^[0-9a-f]{64}$/);
});

test('registry: buildV2PublishArgs carries every v2 field', () => {
  const { args, commitments } = buildV2PublishArgs({
    claimId: 'b05bf4684960ee83',
    reportHash: 'a'.repeat(64),
    evidenceHash: 'b'.repeat(64),
    policyHash: 'c'.repeat(64),
    expiresAt: 2000000000000000,
    publisherAccountId: PUBLISHER,
    controllerAccountId: CONTROLLER,
    salt: SALT,
  });
  assert.equal(args.claim_id, 'b05bf4684960ee83');
  assert.equal(args.publisher_commitment, '99695b4d7c81cc28405549d2f23381c0401359f84bd92719819919dbbc105d6d');
  assert.equal(args.controller_commitment, 'b1a2adc1632e550f2e078e3e735424d4b4cc380afd996d46e496e2546e901508');
  assert.equal(args.commitment_salt, SALT);
  assert.equal(commitments.publisher_commitment, args.publisher_commitment);
});

test('registry: invalid salts and accounts are rejected', () => {
  assert.throws(() => commitmentHex(PUBLISHER_COMMITMENT_DOMAIN, 'xyz', PUBLISHER), /64 lowercase hex/);
  assert.throws(() => commitmentHex(PUBLISHER_COMMITMENT_DOMAIN, 'A'.repeat(64), PUBLISHER), /64 lowercase hex/);
  assert.throws(() => commitmentHex(PUBLISHER_COMMITMENT_DOMAIN, SALT, ''), /non-empty string/);
  assert.equal(newCommitmentSalt().length, 64);
});

test('registry: isV2Version classifies versions', () => {
  assert.equal(isV2Version('2.0.0'), true);
  assert.equal(isV2Version('2.1.0'), true);
  assert.equal(isV2Version('1.0.0'), false);
  assert.equal(isV2Version(null), false);
  assert.equal(isV2Version(undefined), false);
});

test('registry: probe returns null when get_version is missing (v1)', async () => {
  const version = await probeContractVersion(async () => {
    throw new Error('MethodNotFound');
  });
  assert.equal(version, null);
});

test('registry: probe returns the version when the method exists (v2)', async () => {
  const version = await probeContractVersion(async (method) => {
    assert.equal(method, 'get_version');
    return '2.0.0';
  });
  assert.equal(version, '2.0.0');
});
