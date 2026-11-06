# NEAR AI TEE attestation verification

This document says precisely what the attestation behind a VeilProof AI
summary proves, what it does not prove, and how it is checked. It is the
reference for `src/attestation-verify.js`, `src/ai-analysis.js` and
`api/analyze.js`.

## What the attestation is

A VeilProof AI summary (consistency check or underwriting verdict) is
produced by a model running inside a hardware enclave on NEAR AI Cloud
(Intel TDX on the CPU side, NVIDIA Confidential Compute on the GPU side).
NEAR AI Cloud publishes two kinds of evidence for that run:

1. **Attestation reports** (`GET /v1/attestation/report`), one for the
   gateway and one or more for the model deployment. Each carries an
   Intel DCAP quote (`intel_quote`), an event log (`event_log`), the
   signing identity (`signing_address`, `signing_algo`,
   `signing_public_key`), the TCB info (`info.tcb_info`, including the
   `app_compose` that defines the measured deployment), and, for the
   gateway, the echoed `request_nonce` and `report_data`.
2. **A response signature** (`GET /v1/signature/{completionId}`), which
   signs the exact bytes of one completion. The signed text is
   `<MODEL_ID>:<request_hash>:<response_hash>` when the model TEE
   signs (kind `provider_tee`), or
   `<request_hash>:<response_hash>` when the gateway signs (kind
   `gateway`), where each hash is SHA-256 of the exact request or
   response bytes.

The analysis requests the report **before** the completion, with a
fresh 32-byte random nonce, and always passes `provider=near` and an
explicit `signing_algo` (default `ecdsa`). Without `provider=near`
the model reports may be omitted entirely, which is why the old code
fetched the report without it and could only ever see the gateway
echo.

## The four states

Every analysis returns an `attestation` object with one of four
statuses. The UI shows the word VERIFIED only for the first.

| Status | Meaning |
| ------ | ------- |
| `VERIFIED` | Every required cryptographic check passed (see below). |
| `UNVERIFIED` | Evidence was missing, incomplete, or verification could not be completed. The analysis still ran and the summary is still returned; it is simply not attested. |
| `FAILED` | A cryptographic check failed: a quote did not verify, a binding did not match, a signature did not recover to the expected signer, or the signed text did not match the exact bytes. |
| `EXPIRED` | The evidence passed all checks but is outside its validity window (default 60 minutes from verification). |

Rules that are never broken:

- An arbitrary JSON `"verified"` field from the API is never accepted
  as proof. The only fields trusted are the ones read out of a quote
  after it has been verified, and the signature recovered from the
  signed text.
- A locally calculated SHA-256 hash of the evidence is only a content
  pin (`ref`): it records *which* evidence was checked so a later
  reader can identify it. It is never presented as verification.
- On any failure, or if the official verifier is unavailable, the
  result is `UNVERIFIED` or `FAILED`, never `VERIFIED`.
- A nonce-echo match alone is `UNVERIFIED`. The old code set
  `verifiable: true` on a nonce echo; that result is now relabelled
  `UNVERIFIED`, and summaries published before this change (which
  carry no `status` field) are read as `UNVERIFIED` by the verifier
  page.

## What is checked, in order

### Preflight (before the completion)

1. **Report fetch.** `GET /v1/attestation/report?model=<id>&provider=near&signing_algo=ecdsa&nonce=<64 hex chars>`.
   A fetch failure is `UNVERIFIED` ("attestation unavailable"), not a
   failure of the analysis.
2. **Gateway report required.** The gateway report must be present and
   carry an `intel_quote`. Missing gateway evidence is `UNVERIFIED`.
3. **Model reports required by default.** At least one
   `model_attestations[]` candidate must be present, and **every**
   candidate is verified. A candidate whose model name is not the
   requested model fails the whole preflight. (Set
   `VEILPROOF_ATTESTATION_REQUIRE_MODEL=0` to allow a gateway-only
   result; the status then stays `UNVERIFIED` for the model side and
   the details say so.)
4. **DCAP quote verification.** Each quote is parsed with
   `@phala/dcap-qvl` (`Quote.parse`, then collateral, then `verify`
   against the Phala PCCS, or the Intel PCS via
   `VEILPROOF_ATTESTATION_PCCS_URL`). The three stages are told apart
   on purpose: a malformed quote is `FAILED`, unavailable collateral
   is `UNVERIFIED`, a quote that fails verification is `FAILED`.
   Versions used are at or above 0.3.9, the fix for CVE-2026-22696
   (QE Identity signature verification). Debug quotes are rejected.
5. **TCB / advisory policy.** The verified quote's TCB status must be
   in the accepted set, default `UpToDate, OutOfDate` (the same policy
   the official SDK documents). Advisory IDs are recorded in the
   details; they are not individually allowlisted.
6. **Nonce binding, from the verified quote.** The last 32 bytes of
   the quote's `report_data` must equal the nonce sent in the request.
   The HTTP-echoed `request_nonce` and `report_data` are also checked
   against the sent nonce and the verified quote, and any mismatch is
   `FAILED`. Nothing echoed over HTTP is trusted on its own.
7. **Signing identity binding, from the verified quote.** The first
   32 bytes of `report_data` must equal the signing identity
   zero-padded to 32 bytes (a 20-byte ECDSA address, or a 32-byte
   Ed25519 public key). The signing identity is therefore the one the
   enclave committed to, not the one the JSON claims.
8. **RTMR3 event-log replay.** The `event_log` (a JSON string from the
   gateway, an array from the model) is replayed: only events with
   `imr = 3`, in order, each digested as
   `SHA-384(event_type as 4 little-endian bytes || ":" || event as UTF-8 || ":" || hex-decoded event_payload)`,
   extending from 48 zero bytes. The result must equal the RTMR3 in
   the verified quote. An event that states a digest must state the
   recomputed one.
9. **MRCONFIGID check.** The quote's MRCONFIGID must equal
   `01 || SHA-256(app_compose) || 15 zero bytes`, where `app_compose`
   is hashed as its exact UTF-8 bytes, never parsed and re-serialised.
   The `compose_hash` recorded in the event log must also equal the
   SHA-256 of the same bytes, and the TCB info's `mrtd` and `rtmr3`
   must equal the quote's.
10. **Measurements.** The verified measurements (`mrtd`, `mrconfigid`,
    `composeHash`, `rtmr3`) are always recorded in the details. An
    optional allowlist via `VEILPROOF_ATTESTATION_MEASUREMENTS` (a JSON
    array of `{ mrtd, mrconfigid?, composeHash? }`) makes the check
    strict: a report whose measurements match no entry fails. With no
    allowlist set, the consistency checks above (RTMR3 replay,
    MRCONFIGID, compose-hash cross-check) still run; no image
    provenance is claimed.
11. **Evidence age.** A verified preflight is valid for
    `VEILPROOF_ATTESTATION_MAX_AGE_MS` (default 3,600,000 ms, 60
    minutes, matching the official SDK's deployment-verification
    cache). `expiresAt` is `verifiedAt + maxAgeMs`. A result evaluated
    past `expiresAt` is `EXPIRED`.
12. **Replay protection.** A nonce is recorded in an in-memory store
    only on a successful `VERIFIED` preflight, and a reused nonce
    fails with `FAILED` ("nonce already used"). The store is
    per-process (a serverless instance holds its own); it is not a
    shared store.

### Completion (the model call)

13. **Exact byte retention.** The request body is built once and kept
    as bytes; the response is read as raw bytes (`arrayBuffer`), never
    parsed and re-serialised. `Accept-Encoding: identity` is sent so
    the wire bytes are the hashed bytes. The request and response
    hashes are SHA-256 of those exact bytes.
14. **Signature fetch.** `GET /v1/signature/{completionId}?model=<id>&signing_algo=<algo>`
    is fetched only when the completion returned an `id` **and** the
    preflight is `VERIFIED`; otherwise the result is `UNVERIFIED` by
    construction and no fetch is made. A 404 is retried a bounded
    number of times (default 5 attempts, 1000 ms apart — the signature
    is cached on the serving node and may transiently 404 from another
    node); a final 404 is `UNVERIFIED`. A 2xx response carrying an
    `error_code`/`message` means no signature is available, also
    `UNVERIFIED`.
15. **Signature kind.** `signature_kind` must be exactly
    `provider_tee` or `gateway`. An absent or unfamiliar kind is
    `UNVERIFIED`; the kind is never inferred from the shape of the
    signed text. The text must have the part count its kind requires
    (3 for `provider_tee`, 2 for `gateway`) and must equal the expected
    text built from the exact byte hashes; a mismatch is `FAILED`.
16. **Signer match.** For `ecdsa`, the EIP-191 signer is recovered
    from the signature and the text, and must equal the signing
    address of exactly one verified preflight report — a model report
    for `provider_tee`, the gateway report for `gateway`. Zero
    matches, or more than one, is `UNVERIFIED`. For `ed25519`, the
    signature is verified against the matched preflight key with
    tweetnacl over the UTF-8 text bytes. If the signature response
    carries its own `signing_address`, it must equal the recovered
    signer, else `FAILED`.

### Combining

The final status is `VERIFIED` only when the preflight is `VERIFIED`,
the evidence is not expired, and (when required) the signature is
`VERIFIED`. A `FAILED` preflight or signature stands as `FAILED`
even if the other stage passed. `VERIFIED` therefore means: the
gateway and every model candidate verified as TDX quotes with the
right nonce and signing identity, the event log replayed to the
quote's RTMR3, the deployment compose matched the quote's
MRCONFIGID, and the exact completion bytes were signed by the key of
exactly one of those verified reports.

## Result interface

```js
{
  status: 'VERIFIED' | 'UNVERIFIED' | 'FAILED' | 'EXPIRED',
  method: 'near-ai-cloud-dcap' | 'near-ai-cloud-dcap+response-signature',
  model: 'z-ai/glm-5.3-flash',
  nonceMatched: true | false | null,
  quoteVerified: true | false | null,
  signatureVerified: true | false | null,
  measurementsChecked: true | false | null,
  expiresAt: '2026-11-06T21:00:00.000Z',   // ISO string, or null
  details: { /* per-check evidence: statuses, measurements, advisories */ },
  error?: 'human-readable reason, present when the status is not VERIFIED',
  // legacy / convenience fields, kept for the report format:
  verifiable: true,   // exactly status === 'VERIFIED'
  ref: '<sha256 hex of the evidence as fetched, or null>' // content pin only
}
```

`details.preflight` carries the gateway and per-model report results
(outcome, TCB status, advisory IDs, measurements, nonce and identity
matches, RTMR3 and MRCONFIGID results). `details.signature` carries
the signature kind, the recovered signer, the matched report, and
whether the text matched. A field that was never confirmed is `null`,
never silently `true`.

The verifier page (`public/verify.html`, `src/verify-report.js`,
mirrored in `public/js/verify-browser.js`) consumes this interface
with one extra guard of its own: it accepts `VERIFIED` only when the
nonce, quote, signature and measurements were all confirmed; a
`VERIFIED` claim with a failed check becomes `FAILED`, and one with a
check merely unconfirmed becomes `UNVERIFIED`. A report whose AI
summary carries no `status` field (published before this change) is
read as `UNVERIFIED`, with the panel explaining that the quote,
signature and measurements were not rechecked.

## Policy (environment variables)

All read server side only, in `src/attestation-verify.js`
(`resolveAttestationPolicy`). None is ever sent to the browser.

| Variable | Default | Meaning |
| -------- | ------- | ------- |
| `VEILPROOF_ATTESTATION_TCB_ACCEPT` | `UpToDate,OutOfDate` | Accepted TCB statuses. |
| `VEILPROOF_ATTESTATION_MAX_AGE_MS` | `3600000` | Evidence validity window in ms. |
| `VEILPROOF_ATTESTATION_MEASUREMENTS` | unset | JSON array of `{ mrtd, mrconfigid?, composeHash? }`; when set, measurements must match an entry. |
| `VEILPROOF_ATTESTATION_REQUIRE_MODEL` | `1` | Require at least one verified model report. |
| `VEILPROOF_ATTESTATION_REQUIRE_SIGNATURE` | `1` | Require a verified response signature for `VERIFIED`. |
| `VEILPROOF_ATTESTATION_REQUIRE_GPU` | `0` | Require GPU (NVIDIA) evidence. |
| `VEILPROOF_ATTESTATION_PCCS_URL` | Phala PCCS | Collateral source for DCAP verification. |
| `VEILPROOF_ATTESTATION_SIGNATURE_RETRIES` | `5` | Bounded retries on a 404 signature fetch. |
| `VEILPROOF_ATTESTATION_SIGNATURE_RETRY_DELAY_MS` | `1000` | Delay between signature retries. |

## What is NOT verified (limits, stated plainly)

- **No complete end-to-end chain.** A verified model report, a
  verified gateway report and a verified response signature do not
  form a complete cryptographic chain from model execution through
  gateway processing to the final bytes. This is a property of the
  official protocol itself, not of this implementation: the gateway
  attestation is evidence for the gateway only, not for the model
  environment, and the signature binds the final bytes to a signing
  key, not to the execution that produced them. The official SDK
  states the same limit, and NEAR tracks a proposed provider
  signature plus gateway receipt chain as a future improvement.
- **Same serving instance is not proven.** Instances of the same
  model share one signing key, so a `provider_tee` signature that
  matches a verified model report proves the completion was signed by
  the model's key, not that it came from the same serving instance as
  the report that was verified. A load balancer can serve the same
  hostname from more than one attested instance.
- **GPU evidence is recorded, not verified.** When a model report
  carries an `nvidia_payload`, its presence and its nonce match are
  recorded in the details, but the payload is not sent to NVIDIA
  NRAS and no NRAS verdict is required (`requireGpu` defaults to
  false). The April 2026 audit of this stack found NRAS returning
  persistent FAIL verdicts, and GPU verification is not part of the
  required procedure here; treating an NRAS failure as a hard fail
  would make verification depend on a service that has been observed
  to fail independently of the TDX evidence.
- **TLS is not bound.** The attestation request does not ask for a
  TLS fingerprint and the peer SPKI of the evidence connection is not
  pinned, so `report_data` binds the signing identity only, not the
  TLS session. A man-in-the-middle that could substitute a whole
  attestation response is outside what this check claims to stop; the
  DCAP quote itself is still verified against Intel collateral.
- **Image provenance is not checked by default.** The measurements
  are recorded and can be allowlisted, but no Sigstore or build
  provenance check runs. A measurement allowlist pins *which*
  deployment ran; it does not by itself prove that deployment's image
  was built from a particular source repository.
- **Replay protection is per-process.** The nonce store is in-memory
  in the server process. Two serverless instances do not share it, so
  the same nonce could in principle be accepted twice by two
  different instances. A shared store would be needed for a
  cross-instance guarantee.
- **The verdict is advisory.** Attestation covers the inference, not
  the correctness of the underwriting opinion. The deterministic guard
  in `src/ai-analysis.js` can only tighten a verdict (a thin score
  can never support a lend); the AI can never loosen it.
- **Attestation does not validate the response quality**, secure a
  compromised client, or establish that the model behaved honestly
  beyond what the measurements and the signature cover.

## Tests

- `test/attestation-verify.test.mjs` — 44 tests against the real
  verification code, using a fixture built from a real live
  attestation report (`test/fixtures/near-ai-attestation.json`,
  fetched 2026-11-06 from the public report endpoint; the stub DCAP
  stands in only for the Intel chain and returns the fixture's
  recorded TD values, while `Quote.parse`, the RTMR3 replay, the
  MRCONFIGID check and the signature recovery all run for real).
  Covers forged and modified attestations, replayed nonces, invalid
  signatures, expired evidence, wrong model identity, completion
  response substitution, mismatched inference execution, and missing
  signing evidence. No test asserts a hardcoded `VERIFIED`.
- `test/ai-analysis.test.mjs` — 25 tests, including a happy path that
  drives the real `callNearAi` flow with fixture evidence, a genuine
  provider-tee signature, and the stub DCAP, asserting `VERIFIED`
  with all sub-checks true, and echo-only paths asserting
  `UNVERIFIED`.
- `test/analyze-route.test.mjs` — 9 tests through the real route
  handler, asserting the echo-only shape passes through as
  `UNVERIFIED`.
- `test/attestation-live.test.mjs` — opt-in live test, skipped unless
  `VEILPROOF_ATTESTATION_LIVE=1` and the VeilProof NEAR AI key is set
  in the environment. It runs the real `/api/analyze` handler against
  the live API with real DCAP verification and asserts `VERIFIED`
  with quote and signature checks true. It is not part of the default
  run: it spends one real completion and needs the key, which lives
  in the Secure Vault / Vercel env and is never read back locally.

Live evidence, 2026-11-06: the real gateway and model quotes for
`z-ai/glm-5.3-flash` were fetched from the public report endpoint and
verified against the Phala PCCS with status `UpToDate` and no
advisories; every binding in the list above (nonce, signing identity,
RTMR3 replay, MRCONFIGID, compose hash, TCB measurements) matched
the verified quotes. The live end-to-end run through `/api/analyze`
has not been executed in this environment because the key is not
present locally; run the opt-in live test after deployment (the
deployed server holds the key) or with the key in the environment.

## References

- NEAR AI Cloud verification docs: gateway attestation, model
  attestations, response signatures, quote/nonce/signer bindings,
  verification policy (docs.near.ai, consulted 2026-11-06).
- Example implementation: near-examples/nearai-cloud-verification-example
  (the implementation here is deliberately stricter than the example
  in one place: it never infers the signature kind from the shape of
  the signed text; an absent or unfamiliar `signature_kind` is
  `UNVERIFIED`).
- Python SDK: nearai-inference-sdk (verification behaviour and the
  60-minute deployment cache the policy defaults follow).
- DCAP verifier: @phala/dcap-qvl (pure JS; at or above 0.3.9, the
  CVE-2026-22696 fix). ECDSA recovery: @noble/curves secp256k1.
  Ed25519: tweetnacl.
- Related: `docs/in-enclave-verification.md` (P5) — moving the
  verifier itself into the enclave, which would extend the
  attestation to cover the verification, not just the model's summary.
  That is future work, not feasible on NEAR AI Cloud today.
