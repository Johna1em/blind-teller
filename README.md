# Blind Teller

Buy crypto with an ordinary bank transfer. A private AI reads your bank's payment email inside secure hardware, and a NEAR contract releases the funds. Nobody else sees the email, and nothing about your bank reaches the chain.

- **Hosted demo:** https://test.fastfs.io/blindteller.testnet/blindteller.testnet/index.html
- **Track:** Privacy & Private AI (`privacy`), built at NEAR HACKATHON
- **Status:** testnet prototype with fictional banks. See [What's real](#whats-real) for what runs live today.
- **Licence:** MIT
- **Trust limits:** [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)

## The problem

A smart contract can hold crypto, but it can't see a bank account. People who trade crypto for bank money today have three options:

| Option | What goes wrong |
|---|---|
| A custodial exchange | It holds your crypto and your identity documents |
| A P2P trade with a payment screenshot | Screenshots are easy to fake |
| A zero-knowledge proof of a bank email | Every bank needs its own circuit or parser, and a template change breaks it |

Blind Teller uses the receipt email that banks already send. Banks sign those emails with DKIM. An enclave checks the signature and two private models read the text, so one pipeline can serve any bank in any language without new code per bank. The email stays inside secure hardware.

## Try it

You need a browser. You don't need a wallet, funds or a login. Each order takes under a minute.

| # | Do this | You should see |
|---|---|---|
| 1 | Open the [hosted demo](https://test.fastfs.io/blindteller.testnet/blindteller.testnet/index.html) | Three offers from fictional banks: Meridian Bank (INR), Banco Aurora (BRL) and Rheinbank (EUR) |
| 2 | Click **10** on Meridian Bank | The contract locks 10 USDC. Your browser shows the seller's payment details, which the enclave re-sealed for this browser alone, and an exact amount such as `Rs. 885.01` |
| 3 | Click **Send Rs. 885.01** (your amount may differ) | The fictional bank issues a DKIM-signed receipt email, shown on the page |
| 4 | Click **Hand it to the teller** | The page encrypts the email and sends it to the enclave. In about 15 seconds each check ticks off, including *Read by two private AI models*. The page shows **PAID**, and the contract pays 10 USDC to the demo buyer |
| 5 | Read **On the chain** and **Never on the chain** | The chain holds the order, the amount, a signature and a nullifier. It doesn't hold the email, the bank, or anyone's name |
| 6 | Read **Send it to any chain** | Live NEAR Intents quotes for this amount to Solana, Base, Arbitrum and Ethereum. These are dry quotes, because testnet tokens can't bridge |
| 7 | Click **Check this yourself** | 12 checks run in your browser against public data, and all of them pass |
| 8 | Open **Try to cheat** and run each attack | Each one runs on the real enclave and comes back **REFUSED** with a reason: edited amount, forged bank, lookalike domain, prompt injection, underpayment with a note, wrong payee, failed payment, reused receipt |
| 9 | Open **Proof** and click **Run the checks** | A **VERIFIED** panel appears, with all 28 checks listed below it: NEAR AI's gateway first, then each model, with fresh nonces. They cover the Intel quote, NVIDIA GPUs, boot log and each key's proof on NEAR, then compare the enclave's keys with the contract's. Any failure shows **NOT VERIFIED** and names the check |
| 10 | On **Proof**, choose a recent `.eml` from your own inbox | The enclave checks the real signature against the sender's live DNS and answers **GENUINE** or **REFUSED**. It stores nothing and moves no money |

For step 10, Gmail users can open a message, click the three dots, then **Download message**. Older mail can fail if the sender has rotated its key. Senders with keys under 2048 bits are refused.

## What's real

| Part | Status today |
|---|---|
| Escrow contract | **Live on testnet.** Orders settle with test USDC |
| Model registry | **Live on testnet.** Both model keys are proven on NEAR through `tee-verifier` |
| Enclave (OutLayer, Intel TDX) | **Live.** Decrypts, checks DKIM, runs the rules, signs verdicts |
| Attestation checks | **Live.** They run in your browser with a fresh nonce, in the order NEAR AI's verification docs set out. See [Verification policy](#verification-policy) |
| DKIM on real mail | **Live.** See [Real mail test](#real-mail-test) |
| Two private models on NEAR AI Cloud | **Live.** Every order is read by `z-ai/glm-5.3-flash` and `Qwen/Qwen3.8-27B` over E2EE, and each reply is checked against the model's own signature. The rule-based reader used during development is compiled out of this build, and the contract refuses its verdicts |
| Banks | **Fictional.** Their signing key is public on purpose, and their domains use `.example` |
| Any-chain payout | **Quotes only.** They come from the mainnet 1Click API, and nothing moves |
| Wallet login and a seller page | **Not built.** The demo uses a capped demo buyer, and offers are listed by script |

## How it works

1. **Offer.** A seller locks USDC in the contract and lists a rate and a rail. Their bank details are sealed to the enclave. The contract stores the sealed blob and a hash of it.
2. **Order.** A buyer takes the offer with `take_offer`. The order gets an exact fiat amount, with up to 99 minor units added as a tag, so it can be told apart from other orders.
3. **Reveal.** The enclave re-seals the seller's details to the buyer's one-time key.
4. **Payment.** The buyer pays from their normal bank app, and the bank emails a receipt.
5. **Proof.** The buyer's browser seals the `.eml` to the enclave and calls OutLayer over HTTPS. The email never goes on-chain, even encrypted.
6. **Authenticity.** The enclave checks DKIM (RFC 6376) against keys fetched from two DNS resolvers, which must agree. It requires `From` to be signed and aligned, and refuses `l=`, duplicate headers and keys under 2048 bits.
7. **Reading.** Two different models on NEAR AI Cloud read the email through E2EE to their attested keys. They only copy facts into a fixed schema.
8. **Decision.** Fixed Rust code decides, not the AI. The models must agree, the amount must match the order to the penny, the recipient must match the seller, and every amount in the email must be explained. Text the payer wrote is removed before these checks, and instruction-like text is refused.
9. **Settlement.** The enclave signs a verdict. `settle` rebuilds the order terms, verifies the signature with `env::ed25519_verify`, spends a one-time nullifier, asks the registry whether both model keys are attested, and pays the buyer.

If no proof arrives, the order expires and the USDC returns to the offer.

### Who can see what

| Party | Sees |
|---|---|
| The public and the chain | Order state, token amounts, accounts, verdict signature, nullifier |
| The seller | The payment arriving in their bank account, as with any transfer |
| OutLayer enclave | The email, while it runs, inside TDX |
| NEAR AI model TEE | The email, while it runs, through E2EE |
| Us | Nothing. The site is static and there is no backend |

## What's kept

**Nothing is kept after a response returns.**

- **Our servers:** there aren't any. The site is static files on FastFS, with no backend, database or logs of ours.
- **The enclave:** [`Host`](enclave/src/host.rs) lists everything the enclave can do, and it has no storage call. Each run starts empty, and its memory ends with it. Errors are codes, never content.
- **The browser:** an order lives in the page's memory. The site sets no cookies and uses no local storage. A Content-Security-Policy limits the page to the hosts it needs, and it also blocks the analytics script that the public FastFS gateway adds to pages it serves.
- **The chain:** it keeps the order, the signed verdict and a nullifier. None of them contain the email, the bank or a name.

Two things are outside our control. OutLayer records each run, and the email in that run is sealed to the enclave. NEAR AI keeps response signatures for later lookup. Its gateway only sees the email encrypted, and the model reads it inside its TEE.

## Verification policy

NEAR AI's docs ask each app to [decide what it accepts](https://docs.near.ai/cloud/verification/reference/verification-policy). Anything required that's missing, malformed or unavailable counts as failed.

| Decision | Blind Teller's rule |
|---|---|
| Order of checks | The gateway first, then every model report returned |
| Intel TDX | A verified quote with TCB status `UpToDate` only |
| Debug mode | Refused |
| Signer | `ed25519` only. The verified quote must bind both the key and our nonce |
| GPU evidence | Required for models. NVIDIA's verdict must be `true`, cover our nonce and carry a valid NVIDIA signature |
| Measurements | Each report must match its own compose hash and RTMR3 log. Hashes aren't allowlisted, because they vary across NEAR AI's replicas while keys stay the same |
| Evidence age | In the browser, a fresh nonce on every run. On-chain, a model key stays valid for 21 days after its proof, which covers judging on this testnet deployment. Production should use far less |
| Response signature | Required. It must be `provider_tee`, from the model's proven key, over the exact request and response bytes |
| Image provenance | Not required. `scripts/smoke.ts` reports it, using NEAR's SDK |
| TLS binding | Not required. Browsers can't check it, and the email is encrypted to the model's key anyway |

## Check it yourself

These commands use public data only. They need no keys or account.

```bash
git clone <this repository>
cd blind-teller/web
npm ci
npx tsx scripts/verify.ts
```

`verify.ts` re-checks the latest settled order against the chain: its terms, the enclave's signature, the nullifier and the model keys. To also check the enclave run, pass an order id and the attestation URL from **Raw hardware attestation for this run** on the paid screen:

```bash
npx tsx scripts/verify.ts 9 <attestation url>
```

That adds the active Wasm hash on `outlayer.testnet`, the project id, Intel's signature on the worker's quote, debug mode, the worker's measurements on-chain, and OutLayer's task hash in the quote. Exit code 0 means every check passed. Orders 0 to 11 came from the rule-based reader used during development, so they exit 1 and say why. Later orders were read by the real models.

To check NEAR AI itself from the command line:

```bash
npx tsx scripts/smoke.ts
```

It runs the same checks as the **Proof** page, then repeats attestation with NEAR's official SDK and reports image provenance. With a NEAR AI key it also sends one encrypted completion to each model and verifies its signature.

## Live test results

On 7 Nov 2026 we ran these against the deployed release, with the real models.

| Test | Cases | Result |
|---|---|---|
| Orders on all three banks, settled by the contract | 3 | All settled as `near-ai` in about 16 seconds, and all 12 public checks passed on each |
| The **Try to cheat** attacks | 8 | All refused for the expected reason |
| Harder attacks: fake receipts in notes, hidden text, fake system messages, lookalike payees, notes in Portuguese and German | 18 | All refused |
| Genuine payments with awkward notes, including a very long one | 7 | All accepted |

The harder set found a real bug. The enclave sent each request in one write, and the WASI runtime stops the run on any write over 4,096 bytes. An email only slightly longer than our short samples crashed the run, so most real bank emails would have failed too. No verdict was ever signed on those runs. The enclave now writes in pieces, and 80,000 hostile-input tests guard the parsers.

To repeat the harder set, which uses the demo's public payment key and the project's NEAR AI credit:

```bash
npx tsx scripts/redteam.ts
```

## Real mail test

On 7 Nov 2026 we sent 14 fresh messages from public Linux kernel mailing lists through the deployed enclave, using `web/scripts/inspect.ts`.

| Result | Count |
|---|---|
| Genuine, including `gmail.com`, `kernel.org` and `intel.com` | 9 |
| Refused with `dkim_key_weak`: the sender's key is under 2048 bits | 5 |

A separate December 2025 Gmail message came back `dkim_key_revoked`, because Google no longer publishes that selector.

## Run it locally

Needs Node 24.22 or later. The page talks to the contracts already on testnet.

```bash
cd web
npm ci
npm run dev
```

Then open the URL Vite prints.

To run the tests you also need Rust 1.99.1, which `rust-toolchain.toml` selects:

```bash
cargo test -p teller -p model-registry -p teller-core
```

```bash
cargo test -p blind-teller-enclave --features dev-extractor
```

```bash
cd web && npx vitest run
```

That's 191 tests. They cover the contracts, DKIM, sealing, E2EE against NEAR's vectors, 35 pipeline and attack cases, 80,000 runs of hostile input against every parser, the Verified panel's failure paths, and shared vectors across Rust and TypeScript. [The threat model](docs/THREAT_MODEL.md) names the test behind each attack.

To deploy your own copy, you need a funded testnet account in the NEAR CLI keychain and about 10 NEAR. Build the contracts with `cargo near build non-reproducible-wasm --no-abi` in each contract folder, then:

```bash
BT_CONTRACT=teller.youraccount.testnet cargo build -p blind-teller-enclave --target wasm32-wasip2 --release --features wasi
```

```bash
cd web && BT_ROOT=youraccount.testnet BT_ALLOW_DEV=false npx tsx scripts/deploy.ts
```

Then run `npx tsx scripts/register-models.ts` to prove the model keys on your registry. To test without a NEAR AI key, add the `dev-extractor` feature and leave out `BT_ALLOW_DEV=false`.

To turn on the real models, run `npx tsx scripts/set-model-key.ts` in `web` and paste your NEAR AI key at the hidden prompt. You can instead copy `web/.env.example` to `web/.env`, which git ignores. The script runs `scripts/smoke.ts`, then encrypts the key to OutLayer's keystore, which is the only place the enclave reads it from. It stores nothing if NEAR AI refuses the key.

## Deployed on testnet

| What | Where |
|---|---|
| Escrow | [`teller.blindteller.testnet`](https://testnet.nearblocks.io/address/teller.blindteller.testnet) |
| Model registry | [`models.blindteller.testnet`](https://testnet.nearblocks.io/address/models.blindteller.testnet) |
| Enclave project | `blindteller.testnet/teller` on `outlayer.testnet` |
| Enclave build | `899041fba2c55e7e5ce91b1db6d7d54896486ac6494feba74e1af8928e18f579` |
| Token | `usdc.fakes.testnet` |
| Quote verifier | `tee-verifier-2026-11-02.testnet` |
| Website | On NEAR through FastFS, under `blindteller.testnet` |

[deployments/testnet.json](deployments/testnet.json) has the keys and hashes.

## Reusable parts for NEAR

- **Model registry (`contracts/model-registry`).** NEAR AI Cloud's allowlist lives on Base. This contract proves model signing keys on NEAR through `tee-verifier`, the same verifier the MPC network uses. Anyone can relay a proof, and any contract can call `is_attested(key)`.
- **Rust client for NEAR AI E2EE v3 (`enclave/src/e2ee.rs`, `enclave/src/nearai.rs`).** It runs on OutLayer, matches NEAR's published vectors byte for byte, and requires a `provider_tee` signature rather than a gateway one.
- **DKIM for OutLayer (`enclave/src/dkim.rs`).** A strict verifier with no bank-specific code. New rules on top could prove other facts from signed email, such as a flight delay or a paid invoice. Those rules aren't built.

## Limits

Read [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the full list. The main ones:

- Hardware attestation means a genuine quote from a trusted operator. It isn't a mathematical proof of privacy, and physical attacks on TEEs exist.
- OutLayer's master key holder and NEAR AI's operators are trusted. NEAR AI's measured config is a launcher, so the quote doesn't pin the model weights.
- The Wasm hash proves which binary ran. We haven't shown that another machine can rebuild the same hash from this source.
- A debit alert shows money left an account, not that it arrived.
- The seller sees who paid them. The crypto leg is public unless it's routed privately afterwards.
- Anyone can call the enclave again with the same email. A one-shot limit isn't built.
- P2P fiat exchange is regulated in many countries. Real money needs legal review.

## Repository map

| Path | What it is |
|---|---|
| `contracts/teller` | Escrow: offers, orders, settlement, refunds |
| `contracts/model-registry` | On-chain proofs of model keys |
| `crates/teller-core` | Canonical strings shared by the contract and enclave |
| `enclave` | The OutLayer job: DKIM, sealing, E2EE, rules, verdicts |
| `web/src` | React site, browser crypto and attestation checks |
| `web/src/sandbox` | The fictional banks |
| `web/scripts` | Deploy, register models, host, verify, inspect |
| `fixtures` | Test vectors shared across Rust and TypeScript |
| `docs/THREAT_MODEL.md` | Trust assumptions, attacks and limits |

## Libraries and AI use

**Baseline:** nothing here predates the hackathon. The first commit is dated 7 Nov 2026, and there's no earlier code or template.

**AI code:** the code, tests and docs were written with Claude Code (Claude Opus 5.5), which also read the guides in NEAR's `near-ai-cloud` agent skill and NEAR AI's verification docs.

**AI voice:** the narration in the demo video is an AI voice, made with the open-source Chatterbox model. It isn't a recording of a person. The footage is a real run on the hosted testnet site, and waits that were sped up are labelled on screen.

**Rust:** `near-sdk`, `borsh`, `rsa`, `ed25519-dalek`, `x25519-dalek`, `chacha20poly1305`, `hkdf`, `sha2`, `serde`, `serde_json`, `hex`, `base64`, `getrandom`, `outlayer`, `wasi`.

**Web:** `react`, `@noble/ciphers`, `@noble/curves`, `@noble/hashes`, `@phala/dcap-qvl`, `vite`, `vitest`, `tsx`, `typescript`. `@nearai/inference-sdk` is used only by `scripts/smoke.ts`, as an independent check.

**Services:** OutLayer, NEAR AI Cloud, `tee-verifier`, FastFS, the NEAR Intents 1Click API, Google and Cloudflare DNS-over-HTTPS, Phala's PCCS mirror, and NVIDIA's attestation service.

## Licence

[MIT](LICENSE)
