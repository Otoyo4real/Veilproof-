// Create the dedicated publisher account (publisher.veilproof.testnet) as a
// SUBACCOUNT of the deployer, funded with 0.5 NEAR. Testnet only, VeilProof
// wallets only. Run once: node scripts/create-publisher-account.mjs
//
// The publisher is the admin allowlist account for registry v2: it is the
// only account allowed to publish claims, and it is its own controller for
// the demo claims. The treasury (veilproof-demo.testnet) never appears
// onchain in v2. Keys are written to .testnet-accounts.json (chmod 600,
// gitignored) under role 'publisher' BEFORE creating the account, so a
// later failure never loses the key. Key material is NEVER printed.
import fs from 'node:fs';
import { connect, keyStores, KeyPair } from 'near-api-js';

const RPC = 'https://rpc.testnet.near.org';
const OUT = new URL('../.testnet-accounts.json', import.meta.url);
const PUBLISHER_ACCOUNT = 'publisher.veilproof.testnet';
const SUBACCOUNT_FUND_YOCTO = 5n * 10n ** 23n; // 0.5 NEAR

async function rpcView(accountId) {
  const res = await fetch(RPC, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 'veilproof-check',
      method: 'query',
      params: { request_type: 'view_account', finality: 'final', account_id: accountId },
    }),
  });
  return res.json();
}

const accounts = JSON.parse(fs.readFileSync(OUT, 'utf8'));
const deployer = accounts['deployer'];
if (!deployer || typeof deployer.privateKey !== 'string') throw new Error('deployer account missing in .testnet-accounts.json');
if (accounts['publisher']?.accountId === PUBLISHER_ACCOUNT) {
  console.log(`${PUBLISHER_ACCOUNT} already exists in .testnet-accounts.json — refusing to recreate.`);
  process.exit(0);
}

const keyPair = KeyPair.fromRandom('ed25519');
const publicKey = keyPair.getPublicKey().toString();
accounts['publisher'] = { accountId: PUBLISHER_ACCOUNT, publicKey, privateKey: keyPair.toString() };
fs.writeFileSync(OUT, JSON.stringify(accounts, null, 2) + '\n', { mode: 0o600 });
console.log('wrote publisher key to .testnet-accounts.json (chmod 600) BEFORE creating the account');

const keyStore = new keyStores.InMemoryKeyStore();
await keyStore.setKey('testnet', deployer.accountId, KeyPair.fromString(deployer.privateKey));
await keyStore.setKey('testnet', PUBLISHER_ACCOUNT, keyPair);
const near = await connect({
  networkId: 'testnet',
  nodeUrl: RPC,
  walletUrl: 'https://testnet.mynearwallet.com/',
  helperUrl: 'https://helper.testnet.near.org',
  keyStore,
});
const deployerAccount = await near.account(deployer.accountId);
console.log(`creating subaccount ${PUBLISHER_ACCOUNT} with 0.5 NEAR from ${deployer.accountId} ...`);
await deployerAccount.createAccount(PUBLISHER_ACCOUNT, publicKey, SUBACCOUNT_FUND_YOCTO);
console.log('createAccount tx sent');

// Verify with retries (propagation can take a few seconds).
let verified = null;
for (let attempt = 1; attempt <= 10; attempt += 1) {
  await new Promise((r) => setTimeout(r, 5000));
  const check = await rpcView(PUBLISHER_ACCOUNT);
  if (check.result) { verified = check.result; break; }
  console.log(`  not visible yet (attempt ${attempt}/10)`);
}
if (!verified) throw new Error(`${PUBLISHER_ACCOUNT} not verified onchain after retries — key is saved in .testnet-accounts.json`);
console.log(`VERIFIED ${PUBLISHER_ACCOUNT}: balance ${verified.amount} yoctoNEAR`);
console.log(`explorer: https://testnet.nearblocks.io/address/${PUBLISHER_ACCOUNT}`);
