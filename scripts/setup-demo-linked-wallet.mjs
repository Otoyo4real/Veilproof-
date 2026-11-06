// Create the demo's LINKED wallet (demo2.veilproof.testnet) as a
// SUBACCOUNT of the deployer, and the linking transfer to the primary
// demo wallet. Testnet only, demo wallets only. Run once:
//   node scripts/setup-demo-linked-wallet.mjs
//
// The testnet helper faucet only creates top-level *.testnet accounts,
// so a subaccount must be created by its parent (the deployer).
// The linked wallet proves ownership with a transfer to the primary
// wallet — that transfer hash is the link proof the publish script
// records. Keys are written to .testnet-accounts.json (chmod 600,
// gitignored) under role 'demo-linked' BEFORE any transfer, so a
// later failure never loses the key. Key material is NEVER printed.
import fs from 'node:fs';
import { connect, keyStores, KeyPair } from 'near-api-js';

const RPC = 'https://rpc.testnet.near.org';
const OUT = new URL('../.testnet-accounts.json', import.meta.url);
const LINKED_ACCOUNT = 'demo2.veilproof.testnet';
const PRIMARY_ACCOUNT = 'veilproof-demo.testnet';
const SUBACCOUNT_FUND_YOCTO = 2n * 10n ** 24n; // 2 NEAR
const LINK_AMOUNT_YOCTO = 5n * 10n ** 23n; // 0.5 NEAR

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
if (accounts['demo-linked']?.accountId === LINKED_ACCOUNT) {
  console.log(`${LINKED_ACCOUNT} already exists in .testnet-accounts.json — refusing to recreate.`);
  process.exit(0);
}

const keyPair = KeyPair.fromRandom('ed25519');
const publicKey = keyPair.getPublicKey().toString();
accounts['demo-linked'] = { accountId: LINKED_ACCOUNT, publicKey, privateKey: keyPair.toString() };
fs.writeFileSync(OUT, JSON.stringify(accounts, null, 2) + '\n', { mode: 0o600 });
console.log('wrote demo-linked key to .testnet-accounts.json (chmod 600) BEFORE creating the account');

const keyStore = new keyStores.InMemoryKeyStore();
await keyStore.setKey('testnet', deployer.accountId, KeyPair.fromString(deployer.privateKey));
await keyStore.setKey('testnet', LINKED_ACCOUNT, keyPair);
const near = await connect({
  networkId: 'testnet',
  nodeUrl: RPC,
  walletUrl: 'https://testnet.mynearwallet.com/',
  helperUrl: 'https://helper.testnet.near.org',
  keyStore,
});
const deployerAccount = await near.account(deployer.accountId);
console.log(`creating subaccount ${LINKED_ACCOUNT} with ${SUBACCOUNT_FUND_YOCTO / 10n ** 24n} NEAR from ${deployer.accountId} ...`);
await deployerAccount.createAccount(LINKED_ACCOUNT, publicKey, SUBACCOUNT_FUND_YOCTO);
console.log('createAccount tx sent');

// Verify with retries (propagation can take a few seconds).
let verified = null;
for (let attempt = 1; attempt <= 10; attempt += 1) {
  await new Promise((r) => setTimeout(r, 5000));
  const check = await rpcView(LINKED_ACCOUNT);
  if (check.result) { verified = check.result; break; }
  console.log(`  not visible yet (attempt ${attempt}/10)`);
}
if (!verified) throw new Error(`${LINKED_ACCOUNT} not verified onchain after retries — key is saved in .testnet-accounts.json, re-run the link step only`);
console.log(`VERIFIED ${LINKED_ACCOUNT}: balance ${verified.amount} yoctoNEAR`);

const linked = await near.account(LINKED_ACCOUNT);
const result = await linked.sendMoney(PRIMARY_ACCOUNT, LINK_AMOUNT_YOCTO);
const txHash = result?.transaction?.hash ?? result?.transactionHash ?? null;
if (typeof txHash !== 'string' || txHash.length === 0) throw new Error('link transfer returned no transaction hash');
console.log(`LINK TRANSFER SENT: ${txHash}`);
console.log(`explorer: https://testnet.nearblocks.io/txns/${txHash}`);
console.log(JSON.stringify({ linkedAccount: LINKED_ACCOUNT, linkTxHash: txHash, linkAmountYocto: LINK_AMOUNT_YOCTO.toString() }, null, 2));
