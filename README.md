# VeilProof — Prove your onchain money without revealing your wallet

Prove financial claims about a wallet (volume, balance, history) without revealing
which wallet — because revealing it would expose everything.

Live site: https://veilproof22.vercel.app/ — the deployment with the NEAR AI
key configured, so the AI analysis runs live. (The older
veilproof-delta.vercel.app deployment has no key configured, so its AI says
"not analysed".)

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

## What stays private — and from whom (the honest trade-off)

VeilProof is a **hybrid** privacy model, and it owns that plainly:

| Party | Sees |
| --- | --- |
| The public | Only hashes — the report hash, evidence hash and policy hash on NEAR, and a hash commitment of the address. Never the address, never the amounts, never the tx hashes. A tripwire in the report builder enforces this. |
| The chosen verifier | The address and the data — because they must re-fetch the chain and re-run the checks themselves. That is the point: verification is real, not a trust-me. The prover chooses exactly which verifier gets the disclosure package. |
| The AI backend | Claim-level aggregates only (balances, counts, volume, windows) — never the address, never the tx hashes. The analysis prompt is sanitised by an allowlist, and any address-like field is rejected before it reaches the model. |

What VeilProof does **not** do: hide the address from the verifier, or hide
it from the prover's own browser. A design where even the verifier never
learns the address would need pure zero-knowledge proving; this project chose
the hybrid on purpose, because a lender who cannot re-check the chain is a
lender who has to trust the proof system instead — and that trust is exactly
what the disclosure model removes.

## Separation rules (hard rules from the owner)

- **Wallets:** fresh VeilProof testnet accounts only. Genesis wallets
  (treasury, Core, relay, agents) are never touched. Keys live only in
  `.testnet-accounts.json` (chmod 600, gitignored), never in the repo.
- **GitHub:** VeilProof uses a different GitHub account, not the Genesis one.
  Nothing is pushed or connected until the owner is told it is time.
- **NEAR AI:** a separate NEAR AI key for VeilProof. The Genesis key is never reused.

## Status

Built and live. Registry deployed on NEAR testnet, a demo claim published and
verified onchain (report `86f237c0cf2e3fe6`, publish tx
`B33bZZ6HU6Y1hzi6i7DgUuxwm1jFPt7tXdaPDcUCiECW`), 77/77 tests green, and the
live site runs the AI analysis with a real attested summary. Hackathon: NEAR
Hackathon 2026 (Build Beyond Boundaries), track: Privacy & Private AI.
Deadline: 14 Nov 2026 23:59 UTC. Testnet only.

## Judge in 10 minutes

1. Open https://veilproof22.vercel.app/verify.html and press
   **Try the live demo claim** — a real published claim is verified against
   its onchain record. You should see VALID and all seven checks passing,
   including the AI summary.
2. On the main page, build a report for the demo wallet yourself and press
   **Analyse** — the AI summary comes back attested (verifiable, nonce
   matched).
3. Publish the report (demo wallet, testnet) and verify it the same way.
   Then paste a tampered report — the hash checks fail. Revoke it — the
   validity check fails.

Do X, see Y. Nothing is faked: every check above runs against the live
testnet registry, and a failed check says so.

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
