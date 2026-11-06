# Verifier-bound disclosure (P4)

The disclosure package is the private half of a VeilProof claim: the
wallet address, the full snapshots, the salts, the link signatures. It
is meant for exactly one verifier. Before P4, that was a social rule —
hand the JSON to your verifier and trust them not to forward it. P4
makes it a cryptographic one: the package is sealed so only the
chosen verifier can open it. A verifier who forwards the sealed
package forwards ciphertext, not the data.

## Scheme

Ephemeral-key `nacl.box` — the sealed-box construction, built from
tweetnacl (already a dependency, same library in Node and the browser):

1. The prover generates a fresh ephemeral Curve25519 keypair per
   package and a fresh random nonce.
2. The shared secret is derived from the verifier's public key +
   the ephemeral secret key.
3. The canonical JSON of the disclosure package is encrypted under
   that shared secret. `nacl.box` is authenticated encryption
   (Poly1305), so any tampering with the ciphertext, nonce or
   ephemeral key fails the open.
4. The sealed package ships `{ version, verifierKeyFingerprint,
   ephemeralPublicKey, nonce, ciphertext, expiresAt }`. It contains
   no plaintext: not the address, not a salt, not a tx hash, not a
   balance (covered by `test/crypto-box.test.mjs`).

The verifier derives the same shared secret from the ephemeral
public key + their secret key, and opens it. The verifier never
needs the prover's key; the prover never learns the verifier's
secret key; neither side needs a shared secret set up in advance.

## The verifier's key is NOT their NEAR key

The verifier's encryption key is a **separate Curve25519 keypair**,
generated with `newVerifierKeypair()` — not their NEAR ed25519
signing key. Two reasons:

- ed25519 keys cannot be used directly for `nacl.box` (the box needs
  a Curve25519 key). Converting an ed25519 key to Curve25519 is
  possible mathematically, but it is not what the libraries expose,
  and it would tie the encryption key to the signing key.
- Reusing a signing key for encryption is poor practice: a
  compromise of one purpose compromises the other.

The verifier publishes their encryption public key (base64) and the
prover encrypts to it. How the prover learns the key is out of scope
here — in practice the verifier hands it over with their request.
If the prover wants proof the key really belongs to that verifier,
the verifier can sign the public key with their NEAR key (a NEP-413
signature over the key, checked against the chain's access-key list,
the same mechanism as the link proof). That binding is not built
yet; the fingerprint is the weaker check that exists today.

The fingerprint is the SHA-256 of the verifier's public key, so the
verifier can confirm a sealed package is addressed to them before
trying to open it. (Decryption itself is the real proof: if it
opens, it was sealed to this key.)

## Expiry

The sealed package carries `expiresAt` (nanosecond epoch, same units
as the report). `openDisclosurePackage` rejects an expired package
**before** decrypting. Callers pass the report's `expiresAt`, so the
sealed package dies when the report does. The report's own expiry is
still checked by `verifyReport` — the package expiry is an
additional, earlier gate. A sealed package that outlived its report
would be useless anyway: the report it belongs to is expired.

## How to use it

**CLI** — `node scripts/agent-prove.mjs --keys … --policy … --verifier-key <base64>` writes `disclosure-encrypted.json` next to the plaintext `disclosure.json`, expiring with the report, and prints the verifier key fingerprint. The plaintext file is still written (the prover keeps it); only the sealed file is shared.

**Prover page** — after building a report, paste the verifier's
encryption public key and click "Encrypt disclosure for this
verifier". The sealed package downloads as JSON; the page never
shows the ciphertext.

**Verify page** — paste the sealed package in the disclosure box and
your verifier secret key in the key field (or click "Generate
verifier keypair" first — it fills the secret key in and shows the
public key to give the prover). The page opens the package locally,
in the browser, rejects it if expired, and then verifies exactly as
with a plaintext package. The secret key never leaves the browser.

## What P4 does and does not do

- It binds the disclosure package to one verifier. It does **not**
  stop that verifier from reading the data and re-sharing it
  themselves — once opened, the data is in their hands. What it
  stops is everyone else: a forwarded sealed package, an intercepted
  file, a leaked download link.
- It does **not** hide the report: the public report (predicates +
  band) is still public, by design.
- It does **not** change the audit: the privacy audit
  (`docs/privacy-audit.md`) measures what the *public* report leaks,
  and P4 leaves the public report unchanged. P4 protects the
  disclosure package in transit, which the audit's threat model
  assumes reaches only the intended verifier — P4 is what enforces
  that assumption.
- The registry-owner linking limit (P1) is untouched: the onchain
  claim still records who published it, and publish timing still
  correlates claims from the same wallet. P4 seals the disclosure
  package, not the registry record.
