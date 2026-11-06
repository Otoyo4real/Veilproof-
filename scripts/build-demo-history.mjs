// Build a small real onchain history for the VeilProof demo prover wallet.
// Sends a few small testnet transfers between the two fresh VeilProof accounts
// (veilproof.testnet <-> veilproof-demo.testnet). No Genesis wallets involved.
// Records the tx hashes in demo/history.json for the demo + engine checks.
// Run: node scripts/build-demo-history.mjs
import fs from 'node:fs';
import { connect, keyStores, KeyPair, utils } from 'near-api-js';

const ACCOUNTS_FILE = new URL('../.testnet-accounts.json', import.meta.url);
const OUT = new URL('../demo/history.json', import.meta.url);

const accounts = JSON.parse(fs.readFileSync(ACCOUNTS_FILE, 'utf8'));
const keyStore = new keyStores.InMemoryKeyStore();
for (const role of ['deployer', 'demo-prover']) {
  const a = accounts[role];
  await keyStore.setKey('testnet', a.accountId, KeyPair.fromString(a.privateKey));
}
const near = await connect({
  networkId: 'testnet',
  nodeUrl: 'https://rpc.testnet.near.org',
  walletUrl: 'https://testnet.mynearwallet.com/',
  helperUrl: 'https://helper.testnet.near.org',
  keyStore,
});

const transfers = [
  { from: 'deployer', to: 'demo-prover', amount: '1' },
  { from: 'demo-prover', to: 'deployer', amount: '0.5' },
  { from: 'deployer', to: 'demo-prover', amount: '0.25' },
  { from: 'demo-prover', to: 'deployer', amount: '0.1' },
];

const records = [];
for (const t of transfers) {
  const fromId = accounts[t.from].accountId;
  const toId = accounts[t.to].accountId;
  const account = await near.account(fromId);
  console.log(`sending ${t.amount} NEAR ${fromId} -> ${toId} ...`);
  const outcome = await account.sendMoney(toId, utils.format.parseNearAmount(t.amount));
  const hash = outcome.transaction_outcome.id;
  console.log(`  tx ${hash} status ${outcome.transaction_outcome.outcome.status}`);
  records.push({ hash, senderId: fromId, receiverId: toId, amountNear: t.amount });
}

fs.writeFileSync(OUT, JSON.stringify({ accountId: accounts['demo-prover'].accountId, transfers: records }, null, 2) + '\n');
console.log('wrote demo/history.json with', records.length, 'transfers');
