// Redeploy veilproof_registry code to the EXISTING registry.veilproof.testnet.
// Code-only upgrade: no account creation, NO new() call (state is already
// initialized). Safe only when the state layout is unchanged — the 2026-11-06
// fix only adds #[payable] to publish_claim, so the struct is identical.
// Uses ONLY the VeilProof registry key. No Genesis wallets.
// Run: node scripts/redeploy-registry.mjs
import fs from 'node:fs';
import { connect, keyStores, KeyPair } from 'near-api-js';

const ACCOUNTS_FILE = new URL('../.testnet-accounts.json', import.meta.url);
const WASM = new URL('../contract/target/near/veilproof_registry.wasm', import.meta.url);
const REGISTRY_ID = 'registry.veilproof.testnet';

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

const wasm = fs.readFileSync(WASM);
console.log(`deploying ${wasm.length} bytes ...`);
await registryAccount.deployContract(wasm);
console.log('WASM deployed');

const after = await registryAccount.state();
console.log('code_hash after:', after.code_hash);
if (before.code_hash === after.code_hash) throw new Error('code_hash unchanged — redeploy did not take effect');

// Verify the contract still answers: missing claim must be invalid, get_claim null.
const valid = await registryAccount.viewFunction({
  contractId: REGISTRY_ID,
  methodName: 'is_claim_valid',
  args: { claim_id: 'does-not-exist' },
});
const claim = await registryAccount.viewFunction({
  contractId: REGISTRY_ID,
  methodName: 'get_claim',
  args: { claim_id: 'does-not-exist' },
});
console.log('is_claim_valid(missing):', valid, '| get_claim(missing):', claim);
if (valid !== false || claim !== null) throw new Error('verification failed');
console.log('REDEPLOY OK:', REGISTRY_ID);
