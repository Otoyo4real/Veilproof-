// Create the fresh VeilProof testnet accounts via the NEAR testnet helper faucet.
// No Genesis wallets, keys, or funds are involved: the helper funds each new
// account with 10 testnet NEAR. Run once: node scripts/create-testnet-accounts.mjs
// Keys are written ONLY to .testnet-accounts.json (chmod 600, gitignored).
import fs from 'node:fs';
import { KeyPair } from 'near-api-js';

const RPC = 'https://rpc.testnet.near.org';
const HELPER = 'https://helper.testnet.near.org/account';
const OUT = new URL('../.testnet-accounts.json', import.meta.url);

const ACCOUNTS = [
  { role: 'deployer', accountId: 'veilproof.testnet' },
  { role: 'demo-prover', accountId: 'veilproof-demo.testnet' },
];

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
  const data = await res.json();
  return data;
}

const out = {};
for (const { role, accountId } of ACCOUNTS) {
  const keyPair = KeyPair.fromRandom('ed25519');
  const publicKey = keyPair.getPublicKey().toString();
  console.log(`creating ${accountId} with ${publicKey} ...`);
  const res = await fetch(HELPER, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ newAccountId: accountId, newAccountPublicKey: publicKey }),
  });
  const text = await res.text();
  console.log(`helper HTTP ${res.status}: ${text.slice(0, 200)}`);
  const check = await rpcView(accountId);
  if (check.result) {
    console.log(`VERIFIED ${accountId}: balance ${check.result.amount} yoctoNEAR`);
  } else {
    console.log(`NOT VERIFIED ${accountId}: ${JSON.stringify(check).slice(0, 300)}`);
    throw new Error(`account ${accountId} not verified onchain`);
  }
  out[role] = { accountId, publicKey, privateKey: keyPair.toString() };
}

fs.writeFileSync(OUT, JSON.stringify(out, null, 2) + '\n', { mode: 0o600 });
console.log('wrote .testnet-accounts.json (chmod 600)');
