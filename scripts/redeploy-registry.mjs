// Registry v1 -> v2 migration runner (one controlled session).
// Deploys the v2 code to the EXISTING registry.veilproof.testnet, then
// IMMEDIATELY calls migrate() (the contract is bricked between the two),
// then verifies the v2 state. Uses ONLY the VeilProof registry key.
// Testnet only. Run: node scripts/redeploy-registry.mjs
//
// Rollback mode (before migrate succeeds only): set ROLLBACK_WASM to the
// v1 rollback file, e.g.
//   ROLLBACK_WASM=contract/target/near/veilproof_registry-v1-rollback.wasm node scripts/redeploy-registry.mjs
// In rollback mode the script deploys the v1 wasm, skips migrate, and
// verifies the v1 state (get_claim returns owner, is_claim_valid true).
import fs from 'node:fs';
import { connect, keyStores, KeyPair } from 'near-api-js';

const ACCOUNTS_FILE = new URL('../.testnet-accounts.json', import.meta.url);
const V2_WASM = new URL('../contract/target/near/veilproof_registry.wasm', import.meta.url);
const REGISTRY_ID = 'registry.veilproof.testnet';
const PUBLISHER_ID = 'publisher.veilproof.testnet';
// All live v1 claims, enumerated onchain via get_owner_claims on
// 2026-11-07 (the doc's list of 5 missed two: 7c063555730c20fb, the old
// v1 demo claim, and 6338dd5177383c8e, the revoked e2e claim). Any id
// missing here is lost to v2.
const CLAIM_IDS = [
  'b05bf4684960ee83',
  'a41d9faaa0a19148',
  '86f237c0cf2e3fe6',
  'bf2518ecb0791e4a',
  '063feb0181ad5577',
  '7c063555730c20fb',
  '6338dd5177383c8e',
];
const MIGRATE_GAS = 100n * 10n ** 12n; // 100 TGas

const rollbackPath = process.env.ROLLBACK_WASM;
const isRollback = typeof rollbackPath === 'string' && rollbackPath.length > 0;
const wasmPath = isRollback
  ? new URL(`../${rollbackPath}`, import.meta.url)
  : V2_WASM;

const accounts = JSON.parse(fs.readFileSync(ACCOUNTS_FILE, 'utf8'));
const registry = accounts.registry;
if (!registry) throw new Error('registry account missing in .testnet-accounts.json');

const keyStore = new keyStores.InMemoryKeyStore();
await keyStore.setKey('testnet', REGISTRY_ID, KeyPair.fromString(registry.privateKey));

const near = await connect({
  networkId: 'testnet',
  nodeUrl: 'https://rpc.testnet.near.org',
  walletUrl: 'https://testnet.mynearwallet.com/',
  helperUrl: 'https://helper.testnet.near.org',
  keyStore,
});
const registryAccount = await near.account(REGISTRY_ID);

const before = await registryAccount.state();
console.log('code_hash before:', before.code_hash);

const wasm = fs.readFileSync(wasmPath);
console.log(`deploying ${wasm.length} bytes from ${isRollback ? rollbackPath : 'contract/target/near/veilproof_registry.wasm'} ...`);
await registryAccount.deployContract(wasm);
console.log('WASM deployed');

const after = await registryAccount.state();
console.log('code_hash after:', after.code_hash);
if (before.code_hash === after.code_hash) throw new Error('code_hash unchanged — redeploy did not take effect');

if (isRollback) {
  // v1 state is still v1-shaped; verify the v1 contract answers again.
  const valid = await registryAccount.viewFunction({
    contractId: REGISTRY_ID, methodName: 'is_claim_valid', args: { claim_id: 'b05bf4684960ee83' },
  });
  const claim = await registryAccount.viewFunction({
    contractId: REGISTRY_ID, methodName: 'get_claim', args: { claim_id: 'b05bf4684960ee83' },
  });
  console.log('is_claim_valid(b05bf4684960ee83):', valid, '| owner:', claim?.owner);
  if (valid !== true || claim?.owner !== 'veilproof-demo.testnet') throw new Error('rollback verification failed');
  console.log('ROLLBACK OK: registry is v1 again, claims untouched');
  process.exit(0);
}

// ---- v2 migration: the contract is bricked until migrate runs. ----
console.log(`calling migrate(admin_publisher=${PUBLISHER_ID}, ${CLAIM_IDS.length} claim ids) ...`);
const migrateResult = await registryAccount.functionCall({
  contractId: REGISTRY_ID,
  methodName: 'migrate',
  args: { admin_publisher: PUBLISHER_ID, claim_ids: CLAIM_IDS },
  gas: MIGRATE_GAS,
  attachedDeposit: 0n,
});
console.log('migrate tx:', migrateResult?.transaction?.hash ?? migrateResult?.transactionHash ?? '(no hash returned)');

// ---- verify v2 state ----
const fail = (msg) => { throw new Error(`migration verification FAILED: ${msg}`); };
const version = await registryAccount.viewFunction({ contractId: REGISTRY_ID, methodName: 'get_version', args: {} });
console.log('get_version:', version);
if (version !== '2.0.0') fail(`get_version is ${version}, expected 2.0.0`);
const admin = await registryAccount.viewFunction({ contractId: REGISTRY_ID, methodName: 'get_admin', args: {} });
console.log('get_admin:', admin);
if (admin !== REGISTRY_ID) fail(`get_admin is ${admin}, expected ${REGISTRY_ID}`);
const publishers = await registryAccount.viewFunction({ contractId: REGISTRY_ID, methodName: 'list_publishers', args: {} });
console.log('list_publishers:', JSON.stringify(publishers));
if (JSON.stringify(publishers) !== JSON.stringify([PUBLISHER_ID])) fail(`list_publishers is ${JSON.stringify(publishers)}`);
const total = await registryAccount.viewFunction({ contractId: REGISTRY_ID, methodName: 'get_total_claims', args: {} });
console.log('get_total_claims:', total);
if (total !== CLAIM_IDS.length) fail(`get_total_claims is ${total}, expected ${CLAIM_IDS.length}`);

const snapshot = JSON.parse(fs.readFileSync(new URL('../migration-snapshot-pre.json', import.meta.url), 'utf8'));
for (const id of CLAIM_IDS) {
  const claim = await registryAccount.viewFunction({ contractId: REGISTRY_ID, methodName: 'get_claim', args: { claim_id: id } });
  const valid = await registryAccount.viewFunction({ contractId: REGISTRY_ID, methodName: 'is_claim_valid', args: { claim_id: id } });
  const beforeClaim = snapshot.claims[id]?.claim;
  const beforeValid = snapshot.claims[id]?.valid;
  console.log(`${id}: valid=${valid} (was ${beforeValid}) revoked=${claim?.revoked} owner_field=${'owner' in (claim ?? {}) ? 'PRESENT' : 'absent'}`);
  if (!claim) fail(`get_claim(${id}) returned null`);
  if ('owner' in claim) fail(`get_claim(${id}) still has an owner field`);
  if (beforeClaim) {
    if (claim.report_hash !== beforeClaim.report_hash) fail(`${id} report_hash changed`);
    if (claim.evidence_hash !== beforeClaim.evidence_hash) fail(`${id} evidence_hash changed`);
    if (claim.policy_hash !== beforeClaim.policy_hash) fail(`${id} policy_hash changed`);
    if (claim.revoked !== beforeClaim.revoked) fail(`${id} revoked changed`);
    if (claim.expires_at !== beforeClaim.expires_at) fail(`${id} expires_at changed`);
  }
  if (valid !== beforeValid) fail(`${id} is_claim_valid changed (${beforeValid} -> ${valid})`);
}
const missing = await registryAccount.viewFunction({ contractId: REGISTRY_ID, methodName: 'get_claim', args: { claim_id: 'does-not-exist' } });
const missingValid = await registryAccount.viewFunction({ contractId: REGISTRY_ID, methodName: 'is_claim_valid', args: { claim_id: 'does-not-exist' } });
console.log('get_claim(does-not-exist):', missing, '| is_claim_valid(does-not-exist):', missingValid);
if (missing !== null || missingValid !== false) fail('missing-claim checks wrong');
console.log(`MIGRATION OK: ${REGISTRY_ID} is v2.0.0, ${CLAIM_IDS.length} claims migrated, hashes preserved, no owner field.`);
