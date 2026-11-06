# VeilProof improvements 1 + 4 — DRAFT plan (prepared 2026-11-06)

Status: research + plan only. Nothing here is built, integrated, or promised to
any outside party. Deadline for the hackathon submission is 14 Nov 2026 23:59
UTC; the realistic scope before then is the Genesis integration (below) plus
this design. Multi-chain code is a post-deadline build unless time frees up
after improvements 2, 3 and 5 land and pass tests.

## 1. A real consumer — the honest picture

No outside marketplace, lender or agent platform accepts a VeilProof report
today, and none will integrate one in the 8 days left before the deadline.
Any claim otherwise would be invented. The consumers below are ranked by how
real the integration path is, not by how impressive they sound.

### First live consumer: Genesis (Isaiah's own project — the only one he controls)

Genesis already has the exact moment VeilProof is for: strangers paying each
other. It has an open job board (jobs pay 0.01 NEAR on PASS via Core escrow),
an arena, and a marketplace with escrow (buy_nft pays seller 95% + 5% to
treasury). Concrete integration, all inside projects Isaiah owns:

- **Job posters prove they can pay before posting.** A job poster attaches a
  VeilProof reportId showing sustained balance ≥ the job prize. Genesis
  verifies it with the existing verifier (one click, no new trust).
- **Marketplace buyers prove funds before a high-value buy/breed.** Same
  pattern: reportId attached to the buy, verified before escrow moves.
- **The demo writes itself.** Two of Isaiah's own live projects, one proving
  funds to the other, both verifiable onchain — that is a stronger submission
  story than any cold outreach, and it needs no one's permission.

This is the one consumer to build before the deadline. It also answers the
"use case" doubt directly: the use case is agent-to-agent commerce, and the
first two agents doing it are his.

### Outreach list (contact after the deadline, or a short message before it — no integration promised)

- **NEAR Private OTC** (Unstoppable DeFi track, listed on nearhackathon.com's
  public build log, checked 2026-11-06): OTC deals are exactly the
  prove-you-can-pay-before-settlement moment. A VeilProof report is the
  natural pre-trade check for an OTC desk that does not want wallet addresses
  on the public record.
- **Veto, Allowance, LeashPay, NEAR Agent Spend Guard** (AI Security &
  Defense + Agent Economy tracks, same build log): spending guards and
  policy engines that decide whether an agent may spend. They need the other
  side of the same question VeilProof answers — whether a counterparty is
  good for it. Complementary, not competing.
- **NEAR AI Agent Market:** NEAR AI announced 8 new jobs where builders bid
  and get paid in USDC if selected. An agent bidding for paid work could
  attach a VeilProof report as proof it can post collateral or cover a
  failure bond. This is a platform-level conversation, not an 8-day
  integration.

### What NOT to claim

- Do not name any of the above as a partner, user or integration in the
  submission unless they have actually agreed. "Designed for" is fine;
  "integrated with" is not, until the code exists.
- Gloam (the official partner SDK for shielded balances/payments) is a
  privacy neighbour, not a consumer: it hides balances, VeilProof proves
  them. Worth one sentence in the submission as adjacent work, not as a
  partner.

## 4. Multi-chain aggregation — design

### Why it matters, and why it is not a pre-deadline build

Real agent treasuries span NEAR, EVM chains and Solana. A NEAR-only score is
a demo; a multi-chain score is the portable reputation the pitch promises.
But each chain needs its own snapshot adapter, its own sampling, its own tx
verification and its own link proof, and each one must be verified live
before the submission means anything. That is a second project in 8 days,
while improvements 2, 3 and 5 are still landing. Ship the design + the
interface now; build the first adapter after the deadline (or after 2/3/5
are green and tested, if a full day frees up).

### The interface (what a chain adapter must provide)

Today `src/onchain.js` is NEAR testnet RPC only (`fetchAccountSnapshot`,
`sampleBalanceHistory`, tx verification by hash). A chain adapter is a module
with the same shape, per chain:

- `fetchSnapshot(account, txHashes, { balanceSamples })` → `{ account:
  { accountId, amount, locked }, txs: [{ hash, senderId, receiverId,
  amountYocto, status, blockTimestampNs, blockHeight }], balanceSamples? }`
- `sampleBalanceHistory(account, { windowHours, samples, heights })` →
  balance readings at past heights, aligned across wallets by height.
- `fetchAccessKeys(account)` → public keys, for the link-proof binding.
- `verifyLinkSignature(...)` → per-chain signature scheme (NEP-413 on NEAR,
  EIP-191 / EIP-712 personal_sign on EVM, Solana ed25519 `signMessage`).

The claims engine, score and verifier stay chain-agnostic: they already work
on `{ account, txs, balanceSamples }` and never see a chain name. Only the
snapshot layer and the link proof change per chain. Amounts must be
normalised to a common unit before scoring — yocto for NEAR, wei for EVM,
lamports for Solana — with the conversion fixed in the policy, not guessed
at verify time.

### First adapter: BSC (not Solana, not Ethereum mainnet)

- Isaiah's home chain for agents: otoyo4real.ai / steve54.ai, MegaBull and
  every BNB mint live there, so a BSC adapter proves the design on wallets
  he already holds, with real history instead of a fresh testnet account.
- Sampling maps cleanly: `eth_getBalance(address, blockNumber)` at past
  block heights is the direct analogue of NEAR's `sampleBalanceHistory`.
  Tx verification is `eth_getTransactionReceipt` + `eth_getTransactionByHash`.
- Link proof is EIP-191 `personal_sign` of the same link statement
  ("VeilProof link: <linked> -> <primary>"), verified with `ecrecover`
  against the linked address — no transfer, no gas, same privacy gain as
  the NEP-413 proof already built for NEAR.
- Testnet first (BSC testnet / Sepolia-style), mainnet only with explicit
  approval, following the same rule as Genesis: testnet until he says so.

### After BSC: Solana

- `getBalance` + `getSignaturesForAddress` + `getTransaction` give the same
  snapshot shape; link proof is the Solana wallet `signMessage` standard.
  Isaiah already holds a Binance Solana wallet, so test data exists — but
  Solana is second because the EVM adapter reuses the most existing
  knowledge (BSC wallets, MegaBull, PancakeSwap history).

### What the submission should say about multi-chain

One honest paragraph: the snapshot interface is chain-agnostic, the BSC
adapter design (sampling by block height, EIP-191 link proof) is specified in
this file, and the NEAR implementation is the proof it works. Do not claim
multi-chain support exists until an adapter passes a live end-to-end test.

## Track reframe — REJECTED by Isaiah 2026-11-06

`submission-prep.md` lists Privacy & Private AI as primary and Agent
Economy as secondary, and that stays. Isaiah was asked whether to flip
the order and said he needs it to be privacy — so the flip below is
rejected, do not re-suggest it. Privacy is the track; agent commerce is
the use case inside it, not a replacement for it.

(Original suggestion, kept for the record: given his doubt that the
privacy use case alone wins, the stronger framing was thought to be
Agent Economy primary — proof-of-funds for agent commerce — with
Privacy secondary as the mechanism. He said no.)
