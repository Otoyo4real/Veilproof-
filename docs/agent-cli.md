# VeilProof agent CLI

Prove a treasury from the command line — no website, no browser, no
wallet app. An agent (or a script acting for one) runs
`scripts/agent-prove.mjs`, gets a report + disclosure package, and
optionally publishes the hashes onchain.

## Quick start

```sh
node scripts/agent-prove.mjs \
  --keys keys.json \
  --policy examples/agent-policy.json \
  --txs txs.json \
  --sample-window 24 \
  --out ./veilproof-out
```

That is a **dry run**: it builds the report and disclosure package
and verifies them locally, but publishes nothing. Add `--publish` to
put the hashes onchain (0.01 NEAR deposit, 100 TGas, signed with the
primary key).

## Keys file

```json
{
  "primary": { "accountId": "agent.testnet", "privateKey": "ed25519:..." },
  "linked": [
    { "accountId": "treasury2.testnet", "privateKey": "ed25519:..." }
  ]
}
```

- `chmod 600` the file. The CLI warns if it is readable by others.
- Private keys are never printed, logged or sent anywhere. The only
  things that leave the machine are read-only NEAR RPC calls, the
  optional underwriting call (claim-level data only, see below), and
  the publish transaction when `--publish` is given.
- The CLI confirms each key belongs to its account (against the
  chain's access key list) before doing anything with it, so a
  wrong-keys-file fails early with a clear message.

## Linked wallets: proved by signature

Linked wallets are proved with a **NEP-413 signature** over the link
statement (`VeilProof link / Linked wallet: X / Primary wallet: Y`),
signed with the linked wallet's key from the keys file. No transfer,
no gas, and no public onchain record connecting the wallets. The
transfer method still works in the website and in old reports, but
the CLI only ever signs — it never sends a linking transfer.

## Policy file

A JSON object of claim thresholds (see
`examples/agent-policy.json`). The policy is published by hash with
the report, so a verifier re-runs the exact same rules. A
`policyVersion` field in the file is read as the report's policy
version and stripped from the hashed policy object.

## Tx file

JSON: either a plain array of `{ hash, senderId? }` or an object
with a `transfers` array (the `demo/history.json` shape). An entry
belongs to a wallet when that wallet sent it, received it, or the
entry names no counterparty (a bare hash is assumed to be the
wallet's own). A linked wallet needs no txs at all — its snapshot
can be balance-only.

## Balance sampling

`--sample-window <hours>` reads the balance at past block heights
(`--samples` readings, default 4), so the report can prove a balance
was HELD, not just deposited an hour ago. The account must be older
than the window. If the requested window fails, the CLI halves it
down to 0.25h before giving up. Linked wallets reuse the primary's
exact sample heights, or the sustained/time-weighted claims refuse
to run.

## Underwriting

By default the CLI asks the live site (`--site`, default
https://veilproof22.vercel.app) for an attested underwriting
summary: POST `/api/analyze` with `{ mode: 'underwriting', claims,
metrics, score, policyVersion }`. That is claim-level data only —
never an address, snapshot or tx hash. The returned summary is
attached to the report. If the call fails, the CLI **warns and
continues without an AI summary** — a report without AI is still a
valid, verifiable report. Pass `--no-underwrite` to skip the call.

## Dry run vs publish

- **Dry run (default):** the 9 checks run against the locally
  computed hashes and are labelled a local check — the onchain
  record does not exist yet, so nobody else can verify the report.
- **`--publish`:** the hashes go onchain, then the CLI re-verifies
  against the REAL onchain record (`get_claim` +
  `is_claim_valid`). Only then is the report verifiable by anyone
  holding the disclosure package.

## Output

`--out <dir>` (default `./veilproof-out`) receives `report.json`
(public — share it), `disclosure.json` (private — send it only to
the chosen verifier), and `policy.json`. The CLI also prints a
summary: report ID, score, verdict, the 9 checks, and the publish
transaction hash when published.

## Exit codes

0 on success (all 9 checks pass), 1 on any failure. A failing claim
refuses to build a report — lower the thresholds or fix the data.
