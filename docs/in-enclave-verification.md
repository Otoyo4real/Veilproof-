# In-enclave verification (P5) — future work, not feasible today

## What P5 would mean

Today the trust in a VeilProof claim rests on two separate things:

1. **Deterministic verification in public code.** The verifier
   (`src/verify-report.js`, mirrored in the browser) re-fetches the
   chain data from the disclosure package, re-runs the claims engine
   and the score, and checks the hashes. Anyone can run it, anyone
   can read it, and the result does not depend on trusting any
   server. This is the part that makes a claim verifiable.
2. **An attested AI summary.** The underwriting verdict comes from
   NEAR AI Cloud, which runs the model inside a hardware enclave
   (Intel TDX + NVIDIA Confidential Compute) and attests that the
   stated model ran on the stated code. The attestation covers the
   *inference* — that this model produced this summary. The verdict
   is advisory only and is never a validity condition.

P5 would move part (1) into the enclave as well: the verifier
itself would run inside a TEE, re-fetch the chain data, re-run the
claims and the score, and sign the verdict — so the attestation
would cover the *verification*, not just the model's summary. A
verifier who cannot or will not run the code themselves could then
trust the enclave's attestation that the verification was performed
correctly, on the genuine chain data, by the published verifier code.

## Why it is not feasible on NEAR AI Cloud today

NEAR AI Cloud is an **inference-only** service. Its public API is:

- `GET /v1/models` — the model catalog.
- `POST /v1/chat/completions` — OpenAI-compatible chat completions.
- `GET /v1/attestation/report` — the attestation evidence for a
  model run.

That is the whole surface (verified 2026-11-06 against the live
catalog and the connector's documented operations). There is no
endpoint that accepts arbitrary code, no function-calling that runs
user logic, and no way for the enclave to make its own RPC calls
back to the NEAR chain. The enclave runs one thing: a model server
(vLLM) serving the model the caller chose. The attestation proves
that model ran in a genuine TEE on the expected code — it says
nothing about any verification logic, because no verification logic
runs there.

So "run the verifier in the TEE" is not a matter of wiring up an
existing feature. It would need a different service: a confidential
compute platform that runs arbitrary code inside a TEE and attests
the code hash (the Phala dstack model that NEAR AI Cloud itself is
built on, for example), with the verifier deployed as a confidential
workload that can reach the NEAR RPC from inside the enclave.

## The honest architecture in the meantime

Do not claim the verification runs in a TEE. It does not. Say
exactly what is true:

- The **verification** is deterministic, public, and re-runnable by
  anyone — that is the trust basis, and it needs no TEE.
- The **AI summary** is attested inference — the TEE proves which
  model produced it, and the deterministic guard can only tighten
  its verdict.
- The TEE protects the *prompt* (the address and snapshots sent for
  analysis are never in it — `src/ai-analysis.js` sends only
  sanitised claims and metrics, never addresses or tx hashes).

That separation is the point: the part that must be trusted
(the verification) is public and re-computable, and the part that
uses the TEE (the AI summary) is advisory. A TEE would not make the
verification more correct — it would only let someone who does not
re-run it trust that it was run. That is worth having, but it is a
convenience for lazy verifiers, not a correctness gain.

## What would make P5 buildable

The trigger condition is a TEE compute offering that:

1. runs arbitrary code (not just model inference) inside the
   enclave, with remote attestation binding the code hash;
2. lets the enclave reach the NEAR RPC (or accepts the snapshots as
   input and re-fetches them itself from inside, so the data is
   genuine by construction rather than caller-supplied);
3. returns a signed verdict that names the attested code hash, so a
   verifier can check the code that ran is the published verifier.

If NEAR AI Cloud adds a code-execution offering, or if VeilProof
deploys the verifier as a confidential workload on a platform like
Phala dstack, P5 becomes a real build: the in-enclave verifier
would fetch the snapshots, re-run the claims engine and the score,
and sign `{ reportId, valid, checks, codeHash }` under an enclave
key whose public half is bound in the attestation. Until then, P5
stays a documented direction, not a claim.

## The attestation that exists today

The AI summary's attestation is verified for real, server side, at
analysis time: DCAP quote verification, TCB policy, RTMR3 replay,
MRCONFIGID, nonce and signing identity binding from the verified
quote, and a response signature over the exact completion bytes. See
`docs/attestation-verification.md` for the full check list, the four
statuses, and the limits — including that even the real procedure
does not yield a complete end-to-end chain, and that a matching
provider-tee signer does not prove the completion came from the same
serving instance as the verified report.
