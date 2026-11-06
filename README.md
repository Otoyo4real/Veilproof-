# VeilProof

Prove an AI agent can pay, without revealing its wallet. VeilProof proves it, and a privacy audit measures how well it stays hidden.

Live site: https://veilproof22.vercel.app/

## Security remediation (2026-11-06)

This repo was audited against a security, privacy and verification remediation spec and the confirmed findings were fixed in code. The audit confirmed six real issues: the registry exposed the treasury wallet as a public owner, the AI attestation was a nonce echo rather than cryptographic verification, the sampling could not prove continuous possession, the score had no manipulation detection, the contract had open publish and no caps, and the UI showed a single VALID badge instead of separate verification fields. All six are addressed in this repo. The Rust contract v2 is implemented and tested (43/43) but **not yet deployed**; the live registry is still v1 and the migration is a separate decision (see [docs/contract-migration.md](docs/contract-migration.md)). The frontend, backend, attestation, sampling and scoring changes go live when this branch is pushed and Vercel deploys it.

## Run it yourself

From a fresh clone, no keys needed:

```
npm install && npm test && npm run audit && npm run demo
```

- `npm test` runs the full suite: engine, verifier, browser parity, and live onchain checks.
- `npm run audit` runs the privacy audit: an attacker with only public data tries to recover a wallet address, link two reports to the same prover, and estimate the exact balance or score, then prints the results table.
- `npm run demo` builds a report from the committed demo history and verifies all 10 checks locally, no wallet or key needed.

## The idea

Agents are starting to pay each other: compute, invoices, OTC deals. Before a deal, the other side wants proof the agent can pay, but publishing a treasury wallet invites targeting, scams and front running. VeilProof is the proof layer for that deal:

- **Multi wallet aggregation.** An agent's treasury is usually spread across wallets. Link them all; balances, volume and activity are aggregated across every linked wallet (a transfer between two of your own wallets is counted once). Each linked wallet proves ownership with a small transfer to the primary wallet, or by signing a link message with its key (NEP 413, no transfer, no gas), either way, only its key holder could have signed it.
- **Time weighted reputation.** A snapshot balance proves nothing, anyone can flash a deposit an hour before the report. VeilProof samples the balance at past block heights, so it proves the LOWEST balance held over the window and the average balance, not a momentary peak.
- **A portable credit score (score v2).** A deterministic 0 to 1000 score from onchain facts only: sustained balance (350), time weighted balance (150), external activity and week spread (150), counterparty diversity (100), external volume (100), no failed transactions (100), staking (50). Activity and volume count external transactions only, wash transfers between the prover's own wallets earn nothing, so a prover washing funds between their own wallets scores 600, not 920. The rules are published in [docs/score-v2.md](docs/score-v2.md) (v1 rules stay in [docs/score-v1.md](docs/score-v1.md) for old reports), and the verifier recomputes the exact score from the same snapshots under the report's own version, a tampered score fails verification. Any app holding the disclosure package can recompute it too, so the score is reusable across apps: one report, many verifiers.
- **An AI underwriter, not an AI verifier.** NEAR AI Cloud (TEE, attested) reads the deterministic score and the claim facts and gives an advisory verdict, lend, lend with limits (with a suggested limit in NEAR), or decline. The verdict is advisory by design: it never changes a report's validity, and a deterministic guard turns any 'lend' on a thin score (< 300) into a 'decline'. The score is the verifiable fact; the AI's judgment is the opinion on top of it.
- **Private by construction.** The data lives on the chain, so it is genuine by definition. A chosen verifier checks the chain directly. The public sees only a report hash on NEAR and salted hash commitments of the addresses, a fresh random salt per report, carried only in the private disclosure package, so two reports from the same treasury cannot be matched from public data, never the addresses, never the amounts, never the transaction hashes.

## What this proves, and what it does not

| Claim | What proves it |
| --- | --- |
| The data is genuine | The verifier refetches it from the chain. Onchain data cannot be typed in by the user. |
| The balance was held, not flashed | Sampled balance history at past block heights: the lowest sampled balance over the window. |
| The wallets are all the prover's | Each linked wallet proves ownership with a transfer to the primary wallet. |
| The credit score is real | The score is deterministic (score v2, published rules): the verifier recomputes it from the same snapshots. A tampered score fails verification. |
| The underwriting opinion is honest | NEAR AI Cloud TEE attestation verified cryptographically: the Intel TDX quote is checked with a DCAP verifier, the nonce and signing identity are read from the verified quote, the event log is replayed to RTMR3, the measurement is checked, and the completion response signature is matched to the exact request and response bytes. Four states: VERIFIED, UNVERIFIED, FAILED, EXPIRED. Advisory only; a thin score can never support a lend. See [docs/attestation-verification.md](docs/attestation-verification.md). |
| The report was not altered | SHA 256 report hash anchored on NEAR; tampering fails verification. |
| The wallet belongs to the prover | The prover signs a challenge with the wallet key (deterministic, auditable). |
| The wallet address stays private | Only a hash commitment is published. The address travels only in the private disclosure package to the verifier the prover chose. In the v2 contract the treasury never appears onchain at all; the publisher is a dedicated account and the controller is named only as a salted commitment. |
| The balance was sampled, not continuously held | The report records the sampling interval, sample count, oldest and newest block, timestamps, lowest observed sampled balance, and completeness. Samples are point in time readings; they do not prove the balance was held continuously between samples. |
| The score is not gamed by wash trading | Manipulation detection flags circular flows, circular chains, shared funders, concentrated counterparties, repeated transfers and internal transfers. Counterparties are labelled UNKNOWN by default; independence is never assumed. Flags never change points; they are shown honestly alongside the score. |

What it does **not** prove: anything about offchain data. VeilProof only ever makes claims about onchain data. The backend fetches chain data for the analysis, that fetch is auditable (the report records the block height and data hash, and the verifier can refetch the same data once the address is disclosed to them).

## What stays private, and from whom (the honest trade off)

VeilProof is a **hybrid** privacy model, and it owns that plainly:

| Party | Sees |
| --- | --- |
| The public | Only hashes, the report hash, evidence hash and policy hash on NEAR, and salted hash commitments of the addresses (fresh random salt per report, so two reports from the same treasury cannot be matched). Never the addresses, never the amounts, never the tx hashes. A tripwire in the report builder enforces this. |
| The chosen verifier | The addresses and the data, because they must refetch the chain and rerun the checks themselves. That is the point: verification is real, not a trust me. The prover chooses exactly which verifier gets the disclosure package. |
| The AI backend | The deterministic score, claim level aggregates and windows only, never the addresses, never the tx hashes. The analysis prompt is sanitised by an allowlist, and any address like field is rejected before it reaches the model. |

What VeilProof does **not** do: hide the address from the verifier, or hide it from the prover's own browser. A design where even the verifier never learns the address would need pure zero knowledge proving; this project chose the hybrid on purpose, because a lender who cannot recheck the chain is a lender who has to trust the proof system instead, and that trust is exactly what the disclosure model removes.

It also does not run the verification inside a TEE. The verification is deterministic, public and rerunnable by anyone, that is the trust basis, and it needs no enclave. The TEE attests only the AI summary. Running the verifier itself in an enclave is documented as future work in [docs/in-enclave-verification.md](docs/in-enclave-verification.md): NEAR AI Cloud is inference only, so there is no code execution surface to run it on today.

## Verification model

A report never shows a single generic VERIFIED badge. It shows five separate fields, each with its own state, so a judge sees exactly what was verified and what was not:

| Field | States | What it means |
| --- | --- | --- |
| `source_status` | VERIFIED, UNVERIFIED, FAILED | The blockchain data was retrieved and processed successfully. |
| `computation_status` | VERIFIED, UNVERIFIED, FAILED | The financial calculations were independently reproduced. |
| `attestation_status` | VERIFIED, UNVERIFIED, FAILED, EXPIRED | The TEE evidence was cryptographically verified. |
| `report_integrity_status` | VERIFIED, UNVERIFIED, FAILED, REVOKED, EXPIRED | The report matches its published commitment and is still valid. |
| `privacy_status` | PRIVATE, PARTIALLY_DISCLOSED, PUBLIC | The treasury identity is not publicly disclosed. |

The overall valid flag is a clearly labelled summary only. It never combines the five fields into a stronger claim than the evidence supports. The verifier page shows each field with green (VERIFIED), amber (UNVERIFIED or LIMITED), or red (FAILED, REVOKED, EXPIRED), plus panels for privacy, attestation, integrity, sampling, and score limitations, and a "How verification works" section in plain language.

## Threat model

VeilProof assumes an adversary who can read all public data (the chain, the registry, the public report, the website) and who wants to learn the treasury wallet, link two reports to the same prover, estimate the exact balance or score, forge a report, or game the score. It does not assume the adversary can break SHA 256, forge an Intel TDX quote, or break the NEAR chain itself. It assumes the prover and the chosen verifier are not colluding to mislead a third party, and that the verifier rechecks the chain honestly.

| Attack | Defence | Residual risk |
| --- | --- | --- |
| Recover the treasury address from the public report | Fresh random salt per report; only a salted hash commitment is published; exact values are sealed in the disclosure package. | None from the report alone (audit: 0/50 recoveries). |
| Link two reports to the same prover | Fresh salt per report; commitments are singletons. | The v1 registry's public owner field still links claims from the same publisher (100% precision). Fixed in contract v2 (not yet deployed). Public transaction senders and history remain correlatable. |
| Estimate the exact balance or score | Public report carries thresholds and a score band only; exact values are in the disclosure package. | Audit: balance error 94.04%, score error 6.22% from public data alone. |
| Forge or tamper with a report | SHA 256 report hash anchored on NEAR; the verifier recomputes it and the claims. | None if the verifier rechecks; a verifier who skips the recheck trusts nothing. |
| Flash funds to fake a balance | Balance is sampled at past block heights; the score uses the lowest sampled balance and the time weighted balance. | Samples are point in time; funds moved between samples are not caught. See the sampling limitation. |
| Wash trade between own wallets | External only scoring; internal transfers earn nothing; manipulation detection flags circular flows, chains, shared funders, concentrated counterparties and repeated transfers. | No onchain data proves who runs an account; sock puppets are flagged as UNKNOWN, not proven independent. |
| Forge the AI attestation | The TDX quote is verified with a DCAP verifier, the nonce and signing identity are read from the verified quote, and the response signature is matched to the exact bytes. | No complete end to end chain from model execution through the gateway to the final bytes, and a matching signer does not prove the same serving instance. Documented in [docs/attestation-verification.md](docs/attestation-verification.md). |
| Publish a claim for someone else's report | Claim IDs are unique; a duplicate publish is rejected. | Anyone can publish any unused claim ID (v1). Contract v2 adds an authorized publisher allowlist. |
| Revoke someone else's claim | Revocation is controller only (v1: owner only). | None in the contract; the controller is named only as a salted commitment in v2. |

## Security assumptions and known limitations

- **Testnet only.** This is a hackathon project on NEAR testnet. Do not deploy it to mainnet without a separate security review.
- **The v1 registry leaks the publisher.** The live registry stores the publisher as a public owner. Contract v2 removes it, but v2 is implemented and tested, not yet deployed. Until the migration runs, the registry owner field is the known linking vector.
- **A dedicated publisher is not anonymous.** NEAR transaction senders and history are public. A publisher account that always publishes for one treasury is correlatable by timing and behaviour. The v2 model reduces the leak; it does not eliminate correlation.
- **Sampling is point in time.** The balance is sampled at selected block heights. It does not prove continuous possession between samples. The report says so plainly.
- **The score does not prove identity, ownership, or creditworthiness.** It measures observable onchain activity. Counterparties are UNKNOWN by default. A sock puppet wallet is flagged, not proven to be a separate person.
- **Attestation has protocol limits.** The verified quote and the verified response signature do not form a complete cryptographic chain from model execution through the gateway to the final bytes, and a matching signer does not prove the same serving instance. The doc states this plainly.
- **The AI verdict is advisory.** It never changes a report's validity. A thin score (< 300) can never support a lend.
- **The nonce replay store is per process in memory.** Serverless instances do not share it. Replay protection is best effort across instances.
- **Verification is deterministic and public.** Anyone can rerun it. That is the trust basis. It does not run inside a TEE; the TEE attests only the AI summary.

## Implemented vs planned

**Implemented and tested in this repo:**
- Multi wallet aggregation, NEP 413 link proof, deterministic claims engine, score v1 and v2, AI underwriter with deterministic guard, salted prover commitments (P2), predicate disclosure (P3), verifier bound disclosure (P4), privacy audit, registry contract v2 (implemented and tested, not deployed), real TEE attestation verification (DCAP quote, RTMR3, MRCONFIGID, response signature), five field verification model, sampling metadata and wide interval warnings, manipulation detection with risk flags and UNKNOWN labels, verifier panels and How verification works, adversarial test suites.

**Planned / future work (not built):**
- Registry v2 migration (implemented, tested, migration plan written; deployment is a separate decision).
- In enclave verification of the verifier itself (NEAR AI Cloud is inference only; documented in [docs/in-enclave-verification.md](docs/in-enclave-verification.md)).
- A relayer for publishing (design discussed; not built; would not make publishing anonymous).
- GPU / NRAS verification of the attestation payload (recorded, not sent to NRAS by default).
- TLS binding for the attestation (not implemented).
- Image provenance / Sigstore checks (measurements recorded, allowlist opt in).
- Multi chain adapters (BSC first; design only in [docs/consumer-and-multichain.md](docs/consumer-and-multichain.md)).

## The score, in one paragraph

score v2 is 0 to 1000 from seven components, all computed from the disclosed snapshots under the policy's windows: sustained balance (lowest sampled balance, 350), time weighted balance (mean sampled balance, 150), activity (external success tx count plus a spread bonus when txs span at least 3 ISO weeks, 150), counterparty diversity (distinct outside counterparties, 100), volume (external volume, 100), no failed transactions (100), staking (50). Activity and volume count external transactions only, a tx counts when at least one endpoint is outside the bundle, so wash transfers between the prover's own wallets earn nothing in those components or in diversity. A feature the prover did not measure scores 0 and is marked unmeasured, the score never hides what it did not see. Bands: 0 to 299 thin, 300 to 599 building, 600 to 799 solid, 800 to 1000 strong. The full rules, with the exact tier thresholds, are in [docs/score-v2.md](docs/score-v2.md); score v1 (six components, activity 200 counting every tx, no diversity) stays in [docs/score-v1.md](docs/score-v1.md) and the verifier recomputes old reports under v1. The score is calibrated for testnet scale treasuries; a mainnet scale recalibration would ship as score v3, and the version field exists so versions are never confused.

## Status

Built and live. Registry deployed on NEAR testnet. The live demo claim is a
multi wallet agent treasury proof: report `b05bf4684960ee83`, publish tx
`3ouNst9DcYkcptEpua7EzqdLDmuY8P8uFsKRgU9TW9PQ`, score band **solid** (the
public report carries the band, not the exact score, the prover's own exact
score is 770), AI underwriting **lend_with_limits, suggested limit 5 NEAR**.
All 10 checks pass onchain, and the full test suite is green (260 tests: 259 passing, 1 skipped by design — the live attestation test, which needs a key).
The live site runs the AI underwriting with a real attested summary. Earlier
demo claims (`a41d9faaa0a19148`, `86f237c0cf2e3fe6`, `bf2518ecb0791e4a`,
`063feb0181ad5577`) stay valid onchain and were superseded, never revoked.
Hackathon: NEAR Hackathon 2026 (Build Beyond Boundaries), tracks: Privacy &
Private AI primary, Agent Economy second. Deadline: 14 Nov 2026 23:59 UTC.
Testnet only.

## Judge in 10 minutes

1. Open https://veilproof22.vercel.app/verify.html and press
   **Try the live demo claim**, a real published multi wallet claim is
   verified against its onchain record. You should see VALID and all ten
   checks passing: prover binding (including the linked wallet), hashes,
   claims (predicates, thresholds and pass/fail, no exact values), the
   recomputed score band (solid), the link proof, validity, and sampling,
   plus the attested underwriting summary.
2. On the main page, build a report for the demo wallet yourself and press
   **Underwrite with NEAR AI**, the verdict comes back attested
   (verifiable, nonce matched), advisory only.
3. Publish the report (demo wallet, testnet) and verify it the same way.
   Then paste a tampered report, the hash checks fail. Revoke it, the
   validity check fails.
4. Seal a disclosure package for one verifier: on the main page, after
   building a report, paste a verifier's encryption public key and press
   **Encrypt disclosure for this verifier**, only that verifier can
   open it, and it expires with the report. On the verify page, paste
   the sealed package and your verifier secret key (or generate a
   keypair there first). See `docs/verifier-bound-disclosure.md`.

Do X, see Y. Nothing is faked: every check above runs against the live
testnet registry, and a failed check says so.

## Layout

- `contract/`: `veilproof_registry` Rust contract (claim hashes only, never
  addresses or amounts in plaintext).
- `src/`: deterministic claims engine, score v2 (v1 kept for old reports), onchain ingestion (NEAR RPC),
  report hashing, attestation handling, AI consistency + underwriting.
- `api/`: Vercel serverless routes (analysis, verification, report).
- `public/`: static frontend.
- `docs/`: published scoring rules (`score-v2.md`, with `score-v1.md` kept for old reports) any app can rerun.
- `test/`: engine + API tests.
- `demo/`: demo script and sample data.

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
11. Verifier refetches the chain data and confirms the claims.
12. A tampered report fails integrity verification.
13. A revoked report is rejected.
