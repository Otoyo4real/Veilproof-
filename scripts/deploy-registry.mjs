// Deploy the veilproof_registry contract to NEAR testnet.
// Uses ONLY the fresh VeilProof deployer (veilproof.testnet). No Genesis wallets.
// Creates registry.veilproof.testnet, deploys the WASM, calls new(), verifies.
// Run: node scripts/deploy-registry.mjs
import fs from 'node:fs';
import { connect, keyStores, KeyPair, utils } from 'near-api-js';

const ACCOUNTS_FILE = new URL('../.testnet-accounts.json', import.meta.url);
const WASM = new URL('../contract/target/near/veilproof_registry.wasm', import.meta.url);
const REGISTRY_ID = 'registry.veilproof.testnet';

const accounts = JSON.parse(fs.readFileSync(ACCOUNTS_FILE, 'utf8'));
const deployer = accounts.deployer;
if (!deployer) throw new Error('deployer account missing in .testnet-accounts.json');

const keyStore = new keyStores.InMemoryKeyStore();
const deployerKey = KeyPair.fromString(deployer.privateKey);
await keyStore.setKey('testnet', deployer.accountId, deployerKey);

const near = await connect({
  networkId: 'testnet',
  nodeUrl: 'https://rpc.testnet.near.org',
  walletUrl: 'https://testnet.mynearwallet.com/',
  helperUrl: 'https://helper.testnet.near.org',
  keyStore,
});
const deployerAccount = await near.account(deployer.accountId);

// Fresh keypair for the registry subaccount (stored for future upgrades).
const registryKey = KeyPair.fromRandom('ed25519');
await keyStore.setKey('testnet', REGISTRY_ID, registryKey);
console.log(`creating ${REGISTRY_ID} with 3 NEAR ...`);
await deployerAccount.createAccount(
  REGISTRY_ID,
  registryKey.getPublicKey(),
  utils.format.parseNearAmount('3'),
);
console.log('subaccount created');

const wasm = fs.readFileSync(WASM);
console.log(`deploying ${wasm.length} bytes ...`);
const registryAccount = await near.account(REGISTRY_ID);
await registryAccount.deployContract(wasm);
console.log('WASM deployed');

console.log('calling new() ...');
await registryAccount.functionCall({
  contractId: REGISTRY_ID,
  methodName: 'new',
  args: {},
  gas: 100_000_000_000_000n,
  attachedDeposit: 0n,
});
console.log('initialized');

// Verify: missing claim must be invalid, get_claim must return null.
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

accounts.registry = {
  accountId: REGISTRY_ID,
  publicKey: registryKey.getPublicKey().toString(),
  privateKey: registryKey.toString(),
};
fs.writeFileSync(ACCOUNTS_FILE, JSON.stringify(accounts, null, 2) + '\n', { mode: 0o600 });
console.log('registry account key stored in .testnet-accounts.json');
console.log('DEPLOY OK:', REGISTRY_ID);
