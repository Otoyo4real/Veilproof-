---
name: veilproof
description: Prove an agent wallet is good for it, without handing over its address. VeilProof reads a NEAR testnet wallet onchain, scores it, and publishes a privacy-preserving credit report whose hashes are anchored onchain. Use this skill to prove a wallet, verify a report, or judge VeilProof.
---

# VeilProof

Privacy is the point. A wallet address is not just a number. It is the whole financial life of the agent that owns it: every balance, every transfer, every counterparty. Hand it over, and anyone can watch its money, forever.

VeilProof lets an agent prove it can pay, without handing over its wallet. The facts come from the chain itself, so they cannot be faked. The address never goes public. The amounts stay sealed.

Live site: https://veilproof22.vercel.app/
Registry contract (NEAR testnet): `registry.veilproof.testnet` (v2.0.0)
Network: NEAR testnet only. Nothing here touches mainnet or real funds.

## What it proves

Agents are starting to pay each other: compute, invoices, OTC deals. Before a deal, the other side wants proof the agent can pay. VeilProof proves the treasury across every wallet the agent holds, proves the balance was HELD and not just deposited an hour ago, and carries a portable credit score any app can recompute from the same public rules.

The public report carries only thresholds and a score band, never the address and never the exact figures. The exact figures go only to the verifier the agent chose, in a private package. A fresh random salt per report means two reports from the same treasury cannot be linked.

## The score

Deterministic, recomputable from the same public rules. No AI, no hidden inputs. Max 1000.

- Sustained balance, max 350: the lowest sampled balance across the window. This is the HELD proof.
- Time-weighted balance, max 150: balance weighted by how long it was held.
- Activity, max 150: external success transactions in the window.
- Counterparty diversity, max 100: distinct outside counterparties.
- Volume, max 100: external volume in the window.
- No failed transactions, max 100: no failed transactions in the window.
- Staked, max 50: staked (locked) balance.

Bands: 0-299 thin, 300-599 building, 600-799 solid, 800-1000 strong. A band is a label, not a lending decision.

Self-transfers between the prover's own wallets earn nothing. A prover cannot inflate its score by moving money between its own wallets.

## The AI underwriting (advisory only)

`POST /api/analyze` on the live site. It reads the deterministic score and claim facts (never the address) and returns a verdict: `lend`, `lend_with_limits`, or `decline`, with a suggested limit. It runs on NEAR AI Cloud with TEE attestation (DCAP verified, model `z-ai/glm-5.3-flash`). The score itself is the verifiable fact; the AI verdict is advisory and never changes the score.

## Prove a wallet

Use the Prove a Wallet page: https://veilproof22.vercel.app/prove.html

1. Connect the wallet (Meteor or MyNearWallet). The connected wallet IS the wallet being proved. There is no address to type and no demo to load.
2. Sign the short NEP-413 ownership challenge. Only the owner of the key could have made it.
3. The snapshot fetches automatically once you sign. Recent transactions are detected automatically from the NEAR Blocks indexer and verified one by one against the chain via RPC. Hashes that cannot be verified are skipped, never invented.
4. Choose the policy. Leave a field blank to skip that claim. Thresholds are in NEAR, windows in days. Sustained and time-weighted claims need balance history sampling; if you fill those in, sampling turns on (24 hours) and the snapshot re-fetches on its own.
5. Evaluate the claims. Each claim passes or fails against the onchain data.
6. Choose what to disclose. Claims you leave out are simply absent from the public report.
7. Optional: underwrite with NEAR AI.
8. Build the report. A fresh random salt is generated per report. The address becomes a salted SHA-256 commitment. The report contains no address and no transaction hash.
9. Publish. This is a transaction from the same wallet. It calls `publish_claim` on `registry.veilproof.testnet` with three hashes: `report_hash`, `evidence_hash`, `policy_hash`. Cost is 0.01 NEAR plus gas. The registry records the signer as the claim owner.

Linking extra wallets: list additional wallet addresses in step 2. Their snapshots are fetched the same way and their balances and transactions are aggregated. Transfers between two of your own wallets are counted once.

## Verify a report

Use the Verify page: https://veilproof22.vercel.app/verify.html

1. Paste the report JSON and the report ID.
2. The verifier fetches the onchain record with `get_claim` on `registry.veilproof.testnet`, then re-runs all 10 checks and re-derives the score from the disclosure package.
3. Verdict is VALID or INVALID. All 10 checks must pass.

The 10 checks: `prover_binding`, `report_hash`, `evidence_hash`, `policy_hash`, `data_hash`, `claims`, `score`, `link_proofs`, `validity`, `attestation`.

To verify by hand from the chain, call the registry view methods over NEAR testnet RPC (`https://rpc.testnet.near.org`):
- `get_claim` with `{"claim_id": "<report id>"}` returns the onchain record: report hash, evidence hash, policy hash, expiry, and whether it was revoked.
- `get_total_claims` returns the number of claims published.

A report is valid only while it is unexpired and unrevoked, and only when every check passes. A tampered threshold, a swapped hash, or a mismatched salt all fail verification.

## Try it without a wallet

Run the live demo: https://veilproof22.vercel.app/demo.html

It verifies a real published claim against the testnet registry and shows every check. The demo claim is `2e8675fa662f06a4`: score 770, band solid, AI verdict `lend_with_limits` with a suggested limit of 3 NEAR, all 10 checks pass, expires 2026-12-07. The claim proves a balance of at least 5 NEAR, an aggregate balance of at least 10 NEAR, sustained and time-weighted balances of at least 10 NEAR, and passing transaction count and volume with no failed transactions in a 30-day window.

## What stays private, and from whom

- The wallet address never appears in the public report. Only a salted commitment does.
- The exact balances, volumes, and transaction hashes are sealed. Only thresholds (for example "balance at least 5 NEAR") and the score band are public.
- Two reports from the same treasury cannot be linked: a fresh random salt per report means the commitments differ.
- The exact figures go only to the verifier the agent chose, in a private encrypted package bound to that verifier.
- Privacy is from the public, not from the chosen verifier. The verifier the agent picks sees the exact figures it needs to check the claims. Nobody else does.

## Honest limits

- The facts are genuine by construction: they are read from the chain, so they cannot be faked. But the score measures observable onchain activity only. It says nothing about offchain debts, offchain income, or whether the agent will behave honestly in a deal.
- The AI underwriting is advisory. It never changes the score and it is not a lending decision.
- An old report can go stale: balances move. Check the expiry and re-verify against the current chain before trusting a report for a live deal.

## For a judge

To judge VeilProof, do these three things, in order:

1. Run the live demo at https://veilproof22.vercel.app/demo.html and confirm it returns VALID with all 10 checks passing for claim `2e8675fa662f06a4`.
2. Verify the same claim by hand: fetch it with `get_claim` on `registry.veilproof.testnet` over testnet RPC and confirm the report hash, evidence hash, and policy hash match the report.
3. Prove a testnet wallet of your own on the Prove a Wallet page, following the steps above, and confirm the report it builds contains no address and no transaction hash, and that publishing anchors its three hashes onchain.

The source is public at https://github.com/Otoyo4real/Veilproof-. The contract, the claims engine, the scoring, and the verifier are all in the repo and all run in the browser, so every claim in this skill is checkable without trusting it.
