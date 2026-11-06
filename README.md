# VeilProof — portable credit score for agents, without revealing the wallet

Prove an agent's treasury across every wallet it holds, prove the balance was HELD and not just deposited an hour ago, and carry a portable credit score any app can recompute — without publishing a single wallet address.

Live site: https://veilproof22.vercel.app/ — the deployment with the NEAR AI key configured, so the AI underwriting runs live. (The older veilproof-delta.vercel.app deployment has no key configured, so its AI says "not analysed".)

## The idea

Agents are starting to pay each other: compute, invoices, OTC deals. Before a deal, the other side wants proof the agent can pay — but publishing a treasury wallet invites targeting, scams and front-running. VeilProof is the proof layer for that deal:

- **Multi-wallet aggregation.** An agent's treasury is usually spread across wallets. Link them all; balances, volume and activity are aggregated across every linked wallet (a transfer between two of your own wallets is counted once). Each linked wallet proves ownership with a small transfer to the primary wallet, or by signing a link message with its key (NEP-413, no transfer, no gas) — either way, only its key holder could have signed it.
- **Time-weighted reputation.** A snapshot balance proves nothing — anyone can flash a deposit an hour before the report. VeilProof samples the balance at past block heights, so it proves the LOWEST balance held over the window and the average balance, not a momentary peak.
- **A portable credit score (score-v2).** A deterministic 0–1000 score from onchain facts only: sustained balance (350), time-weighted balance (150), external activity and week spread (150), counterparty diversity (100), external volume (100), no failed transactions (100), staking (50). Activity and volume count external transactions only — wash transfers between the prover's own wallets earn nothing — so a prover washing funds between their own wallets scores 600, not 920. The rules are published in [docs/score-v2.md](docs/score-v2.md) (v1 rules stay in [docs/score-v1.md](docs/score-v1.md) for old reports), and the verifier recomputes the exact score from the same snapshots under the report's own version — a tampered score fails verification. Any app holding the disclosure package can recompute it too, so the score is reusable across apps: one report, many verifiers.
- **An AI underwriter, not an AI verifier.** NEAR AI Cloud (TEE, attested) reads the deterministic score and the claim facts and gives an advisory verdict — lend, lend with limits (with a suggested limit in NEAR), or decline. The verdict is advisory by design: it never changes a report's validity, and a deterministic guard turns any 'lend' on a thin score (< 300) into a 'decline'. The score is the verifiable fact; the AI's judgment is the opinion on top of it.
- **Private by construction.** The data lives on the chain, so it is genuine by definition. A chosen verifier checks the chain directly. The public sees only a report hash on NEAR and hash commitments of the addresses — never the addresses, never the amounts, never the transaction hashes.

## What this proves — and what it does not

| Claim | What proves it |
| --- | --- |
| The data is genuine | The verifier re-fetches it from the chain. Onchain data cannot be typed in by the user. |
| The balance was held, not flashed | Sampled balance history at past block heights: the lowest sampled balance over the window. |
| The wallets are all the prover's | Each linked wallet proves ownership with a transfer to the primary wallet. |
| The credit score is real | The score is deterministic (score-v2, published rules): the verifier recomputes it from the same snapshots. A tampered score fails verification. |
| The underwriting opinion is honest | NEAR AI Cloud TEE attestation, nonce-bound to the request. Advisory only; a thin score can never support a lend. |
| The report was not altered | SHA-256 report hash anchored on NEAR; tampering fails verification. |
| The wallet belongs to the prover | The prover signs a challenge with the wallet key (deterministic, auditable). |
| The wallet address stays private | Only a hash commitment is published. The address travels only in the private disclosure package to the verifier the prover chose. |

What it does **not** prove: anything about offchain data. VeilProof only ever makes claims about onchain data. The backend fetches chain data for the analysis — that fetch is auditable (the report records the block height and data hash, and the verifier can re-fetch the same data once the address is disclosed to them).

## What stays private — and from whom (the honest trade-off)

VeilProof is a **hybrid** privacy model, and it owns that plainly:

| Party | Sees |
| --- | --- |
| The public | Only hashes — the report hash, evidence hash and policy hash on NEAR, and hash commitments of the addresses. Never the addresses, never the amounts, never the tx hashes. A tripwire in the report builder enforces this. |
| The chosen verifier | The addresses and the data — because they must re-fetch the chain and re-run the checks themselves. That is the point: verification is real, not a trust-me. The prover chooses exactly which verifier gets the disclosure package. |
| The AI backend | The deterministic score, claim-level aggregates and windows only — never the addresses, never the tx hashes. The analysis prompt is sanitised by an allowlist, and any address-like field is rejected before it reaches the model. |

What VeilProof does **not** do: hide the address from the verifier, or hide it from the prover's own browser. A design where even the verifier never learns the address would need pure zero-knowledge proving; this project chose the hybrid on purpose, because a lender who cannot re-check the chain is a lender who has to trust the proof system instead — and that trust is exactly what the disclosure model removes.

## The score, in one paragraph

score-v2 is 0–1000 from seven components, all computed from the disclosed snapshots under the policy's windows: sustained balance (lowest sampled balance, 350), time-weighted balance (mean sampled balance, 150), activity (external success tx count plus a spread bonus when txs span at least 3 ISO weeks, 150), counterparty diversity (distinct outside counterparties, 100), volume (external volume, 100), no failed transactions (100), staking (50). Activity and volume count external transactions only — a tx counts when at least one endpoint is outside the bundle — so wash transfers between the prover's own wallets earn nothing in those components or in diversity. A feature the prover did not measure scores 0 and is marked unmeasured — the score never hides what it did not see. Bands: 0–299 thin, 300–599 building, 600–799 solid, 800–1000 strong. The full rules, with the exact tier thresholds, are in [docs/score-v2.md](docs/score-v2.md); score-v1 (six components, activity 200 counting every tx, no diversity) stays in [docs/score-v1.md](docs/score-v1.md) and the verifier recomputes old reports under v1. The score is calibrated for testnet-scale treasuries; a mainnet-scale recalibration would ship as score-v3, and the version field exists so versions are never confused.

## Separation rules (hard rules from the owner)

- **Wallets:** fresh VeilProof testnet accounts only. Genesis wallets
  (treasury, Core, relay, agents) are never touched. Keys live only in
  `.testnet-accounts.json` (chmod 600, gitignored), never in the repo.
- **GitHub:** VeilProof uses a different GitHub account, not the Genesis one.
  Nothing is pushed or connected until the owner is told it is time.
- **NEAR AI:** a separate NEAR AI key for VeilProof. The Genesis key is never reused.

## Status

Built and live. Registry deployed on NEAR testnet. The live demo claim is a
multi-wallet agent treasury proof: report `a41d9faaa0a19148`, publish tx
`3za51UYQNxrkZQT54ZPyTS8BHwRLKbCMFhZwXHuUFNoE`, score **770/1000 (solid)**,
AI underwriting **lend_with_limits, suggested limit 3 NEAR** (about a quarter
of the ~12.65 NEAR sustained balance — the model did the arithmetic itself;
a deterministic guard would have capped it there anyway). All 9 checks pass
onchain, and the full test suite is green (111/111). The live site runs the AI
underwriting with a real attested summary. Earlier demo claims
(`86f237c0cf2e3fe6`, `bf2518ecb0791e4a`, `063feb0181ad5577`) stay valid
onchain and were superseded, never revoked. Hackathon: NEAR Hackathon 2026
(Build Beyond Boundaries), tracks: Privacy & Private AI primary, Agent
Economy second. Deadline: 14 Nov 2026 23:59 UTC. Testnet only.

## Judge in 10 minutes

1. Open https://veilproof22.vercel.app/verify.html and press
   **Try the live demo claim** — a real published multi-wallet claim is
   verified against its onchain record. You should see VALID and all nine
   checks passing: prover binding (including the linked wallet), hashes,
   claims, the recomputed score (770, solid), the link proof, and validity
   — plus the attested underwriting summary.
2. On the main page, build a report for the demo wallet yourself and press
   **Underwrite with NEAR AI** — the verdict comes back attested
   (verifiable, nonce matched), advisory only.
3. Publish the report (demo wallet, testnet) and verify it the same way.
   Then paste a tampered report — the hash checks fail. Revoke it — the
   validity check fails.

Do X, see Y. Nothing is faked: every check above runs against the live
testnet registry, and a failed check says so.

## Layout

- `contract/` — `veilproof_registry` Rust contract (claim hashes only, never
  addresses or amounts in plaintext).
- `src/` — deterministic claims engine, score-v2 (v1 kept for old reports), onchain ingestion (NEAR RPC),
  report hashing, attestation handling, AI consistency + underwriting.
- `api/` — Vercel serverless routes (analysis, verification, report).
- `public/` — static frontend.
- `docs/` — published scoring rules (`score-v2.md`, with `score-v1.md` kept for old reports) any app can re-run.
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
