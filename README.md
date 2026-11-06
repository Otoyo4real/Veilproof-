# VeilProof — Prove your onchain money without revealing your wallet

Prove financial claims about a wallet (volume, balance, history) without revealing
which wallet — because revealing it would expose everything.

## The idea

A trader or business proves claims like "this wallet did over $1M volume in 30 days"
without revealing the address. The data lives on the chain, so it is genuine by
definition. A chosen verifier (e.g. a lender) checks the chain directly. A TEE
(NEAR AI Cloud) attests the analysis ran correctly. The public sees only a report
hash on NEAR.

## What this proves — and what it does not

| Claim | What proves it |
| --- | --- |
| The data is genuine | The verifier re-fetches it from the chain. Onchain data cannot be typed in by the user. |
| The analysis ran correctly | NEAR AI Cloud TEE attestation, nonce-bound to the request. |
| The report was not altered | SHA-256 report hash anchored on NEAR; tampering fails verification. |
| The wallet belongs to the prover | The prover signs a challenge with the wallet key (deterministic, auditable). |
| The wallet address stays private | Only a hash commitment is published. The address travels only in the private disclosure package to the verifier the prover chose. |

What it does **not** prove: anything about offchain data. VeilProof only ever makes
claims about onchain data. The backend fetches chain data for the analysis — that
fetch is auditable (the report records the block height and data hash, and the
verifier can re-fetch the same data once the address is disclosed to them).

## Separation rules (hard rules from the owner)

- **Wallets:** fresh VeilProof testnet accounts only. Genesis wallets
  (treasury, Core, relay, agents) are never touched. Keys live only in
  `.testnet-accounts.json` (chmod 600, gitignored), never in the repo.
- **GitHub:** VeilProof uses a different GitHub account, not the Genesis one.
  Nothing is pushed or connected until the owner is told it is time.
- **NEAR AI:** a separate NEAR AI key for VeilProof. The Genesis key is never reused.

## Status

Scaffolding in progress. Hackathon: NEAR Hackathon 2026 (Build Beyond Boundaries),
track: Privacy & Private AI. Deadline: 14 Nov 2026 23:59 UTC. Testnet only.

## Layout

- `contract/` — `veilproof_registry` Rust contract (claim hashes only, never
  addresses or amounts in plaintext).
- `src/` — deterministic claims engine, onchain ingestion (NEAR RPC), report
  hashing, attestation handling.
- `api/` — Vercel serverless routes (analysis, verification, report).
- `public/` — static frontend.
- `test/` — engine + API tests.
- `demo/` — demo script and sample data.

## Demo (13 steps)

1. Prover connects a NEAR wallet.
2. Prover picks the wallet to prove claims about and signs a challenge.
3. App fetches the wallet's onchain data (NEAR RPC) and verifies the signature.
4. Deterministic engine computes the claims.
5. NEAR AI Cloud (TEE) analyses the derived metrics.
6. Attestation and signature verification run.
7. Report is generated (claims only, no address).
8. Report hash is published on NEAR testnet.
9. Verifier opens the report link.
10. Verifier receives the private disclosure package (address + data).
11. Verifier re-fetches the chain data and confirms the claims.
12. A tampered report fails integrity verification.
13. A revoked report is rejected.
