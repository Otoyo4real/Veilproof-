# VeilProof architecture

## Stack (proven patterns, reused from Genesis where possible)

- Frontend: static HTML/JS/CSS served by Vercel (same pattern as Genesis).
- Backend: Vercel serverless API routes (Node). No framework magic; small routes.
- Contract: Rust, `cargo-near`, NEAR testnet. Registry only — hashes, no data.
- Wallet: `@fastnear/wallet` (testnet), same as Genesis.
- AI: NEAR AI Cloud, OpenAI-compatible `POST /chat/completions`, with
  attestation verification (nonce-bound, official verifier where available).
  **Key: a separate VeilProof NEAR AI key. Never the Genesis key.**
- Crypto: Web Crypto SHA-256, canonical JSON.

## Modules

1. **Onchain ingestion** (`src/onchain.js`) — NEAR RPC: account view (balance,
   staked), transaction verification by hash (`EXPERIMENTAL_tx_status` / `tx`),
   block height recording. No indexer dependency for the MVP; the report records
   block height + data hash so any verifier can re-fetch and reproduce.
2. **Claims engine** (`src/claims-engine.js`) — deterministic, tested. Claims:
   balance threshold, staked threshold, account age, tx count in window,
   volume in window (from verified tx list), no failed txs in window.
   The engine never invents numbers; AI never overwrites it.
3. **NEAR AI analysis** (`api/analyze.js`) — derived metrics only (no address,
   no raw history) go to the AI. Structured JSON, Zod-validated.
4. **Attestation** (`src/attestation.js`) — fresh nonce per request; verify
   nonce binding, attestation report, response signature. Statuses:
   VERIFIED / UNVERIFIED / FAILED / PENDING. Never fake a VERIFIED.
5. **Report** (`src/report.js`) — canonical JSON: report id, prover pseudonym
   (hash commitment of the address), claims, threshold results, policy
   version, AI summary, evidence refs, expiry. SHA-256 report hash,
   evidence hash, policy hash. No address, no amounts in the public report
   beyond the threshold claims the prover chose to disclose.
6. **Registry contract** (`contract/`) — `veilproof_registry` v2:
   `publish_claim`, `get_claim`, `revoke_claim`, `is_claim_valid`,
   plus `get_version`, `get_admin`, `is_authorized_publisher`,
   `list_publishers`, `get_limits`, `get_total_claims`,
   `get_controller_claim_count`, `add_publisher`,
   `remove_publisher`, `migrate`. Stores only: claim id, salted
   publisher and controller commitments + salt, report hash, evidence
   hash, policy hash, created, expiry, revoked — no account id of any
   kind. Publishing is allowlist-only (a dedicated publisher account,
   never a treasury); revocation is controller-only via the salted
   commitment. Duplicate ids rejected, claim ids are printable ASCII
   only, expiry is 1 hour to 365 days, caps are 100 claims per
   controller and 10,000 total. `get_owner_claims` is removed in v2;
   there is no enumeration. Migration from the deployed v1 registry
   is an in-place `migrate()` call — see
   `docs/contract-migration.md` (plan only, not executed).
7. **Selective disclosure** — the disclosure package (address + data + data
   hash) travels privately to the verifier the prover chose. Revocation stops
   future access; it cannot erase what a verifier already downloaded.
8. **Verifier portal** (`public/verify.html`) — enter a claim id, fetch the
   onchain commitment, fetch the disclosure package, verify hashes, check
   expiry/revocation, inspect attestation evidence, see the claims and what
   was NOT disclosed.

## Verification boundaries (the honest core)

- Genuine data: the chain, checked by the verifier. Not the AI, not the hash.
- Correct computation: the TEE attestation, nonce-bound.
- Unaltered report: the SHA-256 hash vs the onchain commitment.
- Ownership: a signature over a challenge, deterministic and auditable.
- Privacy: the address is never published; only its hash commitment is.
- What the backend sees: the address and the fetched chain data (it has to,
  to build the report). What the backend cannot do: alter the data without
  the report hash mismatching what the verifier re-fetches, or forge the
  attestation.

## Separation rules

- Wallets: fresh VeilProof testnet accounts only (`.testnet-accounts.json`,
  chmod 600, gitignored). Genesis wallets untouched.
- GitHub: a different GitHub account. No push/connect until the owner is
  told it is time.
- NEAR AI: a separate VeilProof key. Genesis key never reused.
- Vercel: a separate Vercel project when the time comes (not the Genesis one).

## Testnet accounts (to be created via the helper faucet)

- `veilproof` deployer/treasury (owns the registry contract).
- `veilproof-demo` demo prover wallet (gets a small history built from
  testnet transfers so the demo has real onchain data to prove claims about).

Both funded via `https://helper.testnet.near.org/account` (10 NEAR each on
creation). No Genesis funds involved.
