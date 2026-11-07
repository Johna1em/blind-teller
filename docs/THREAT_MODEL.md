# Threat model

This document says what Blind Teller protects, against whom, and where it stops. Read it as a claim you can test, not as a guarantee.

**One-sentence version:** the public, the chain and the platform never see your email or bank details, provided Intel and NVIDIA hardware behaves and the named operators don't collude against it.

## What's protected

| Data | Who can read it |
|---|---|
| The bank email | The buyer's browser, the OutLayer enclave, and the two NEAR AI model TEEs |
| The seller's payment details | The seller, the enclave, and the buyer of a live order |
| The buyer's bank and name | The seller, through the bank rail itself. Nobody on-chain |

The email never reaches the chain, even encrypted. It travels from the browser to the enclave over HTTPS as ciphertext, sealed to the enclave's key and bound to one order.

## What's public

Order amounts, token amounts, accounts, rates, and the rail are on-chain. The exact fiat amount is public, because the amount is the order's tag.

The seller's sealed payee record is stored on-chain as ciphertext. It holds a payment handle that the seller gives to every buyer anyway, so we accept that risk here. The email, which is far more sensitive, gets no such exception.

## Who could break this

| Party | What they could do | What limits it |
|---|---|---|
| A buyer | Forge, edit or reuse a receipt, or inject instructions | DKIM, nullifiers, fixed rules, two-model agreement |
| A seller | Deny being paid | Release needs no seller action |
| OutLayer's coordinator | See ciphertext and metadata, drop runs | Payloads are sealed. It can deny service, not read |
| OutLayer's key holder | Its docs say the `dao.outlayer.near` key holder can reach the shared master secret outside any enclave. They could derive our keys | **Trusted. This is the largest assumption here** |
| The enclave project's owner | Publish a new version that signs anything | Locking the owner account after the final release (see below) |
| NEAR AI's gateway | Without E2EE it would see plaintext | E2EE v3 to the attested model key |
| NEAR AI's operators | The measured compose is a launcher. Workloads change at runtime through an operator-driven control plane, and model weights aren't measured | **Trusted.** We publish the compose hash for each proven key |
| Whoever controls NEAR AI's Base allowlist | One EOA owns the on-chain compose allowlist | **Trusted.** This is why the registry records compose hashes on NEAR |
| Intel or NVIDIA | Their signatures are the root of the attestation | **Trusted** |
| Someone with physical access to the hardware | TEE.fail (2025) and DDRop (2026) showed quote forgery with physical access | **Trusted operator assumed.** Say "genuine quote, trusted operator", never "provably private" |
| A DNS resolver | Serve a false bank key | Two independent resolvers must agree |
| An RPC node | Invent an order to extract payee details | Two providers must agree, and `reveal` serves one contract |

## Attacks and answers

| Attack | Defense | Tested in |
|---|---|---|
| Edit the amount | DKIM body hash | `attack_edited_amount` |
| Forge the sender | From alignment and the issuer list | `attack_forged_sender` |
| Sign with your own key | The bank's key decides | `attack_right_domain_wrong_key` |
| Lookalike domain | Exact issuer match per rail | `attack_self_signed_email_from_a_lookalike_domain` |
| Add a second `From` | Any covered header appearing more often than signed is refused | `a_prepended_from_header_fails` |
| Append text below the signature | `l=` is refused | `an_appended_unsigned_body_cannot_use_the_length_tag` |
| Re-frame with an unsigned `Content-Type` | Unsigned headers aren't visible to the parser | `an_injected_content_type_cannot_reframe_the_body` |
| Prompt injection in the note | Marker screen, a model-raised flag, fixed rules | `attack_prompt_injection_in_the_note` |
| Pay ₹1, write the full amount in the note | The note is removed, and every amount must be explained | `fooled_models_are_caught_by_the_real_amount` |
| Reuse an email | One nullifier per email | `one_email_cannot_settle_two_orders` |
| Reuse an old email | Signed time against the order's creation | `attack_old_email_from_before_the_order` |
| Move a ciphertext to another order | Associated data binds it to the order | `attack_ciphertext_lifted_from_another_order` |
| Move a verdict to another order | The signature covers `terms_hash`, rebuilt by the contract | `a_verdict_for_another_order_is_refused` |
| Pick a cheaper model | The enclave accepts only its fixed pair | `a_caller_cannot_choose_the_models` |
| Swap the model's prompt | The prompt is compiled in, and the model's signature covers the exact request | `a_swapped_request_is_refused` |
| Accept a gateway signature as a model's | `provider_tee` is required | `a_gateway_signature_is_not_a_model_signature` |

## Known limits

**The note attack isn't fully closed.** A note that fools both models about what the note is, in the same way, while the email's other amounts are all explained, could pass. Per-order caps limit the damage. A production system should keep per-issuer format hints and a seller dispute window.

**Re-rolls.** Anyone can call the enclave again with the same email and keep the best result. The output for a given email should be stable, and a value must appear in the source to count, but a one-shot limit in sealed storage would close this properly. It isn't built.

**A debit alert isn't proof of arrival.** It shows the bank says money left. Transfers can reverse. Use instant, irreversible rails and cap order sizes.

**Bank coverage.** The issuers on the real rails in `enclave/src/policy.rs` are candidates, unverified until tested with a real sample. Some banks send no email, some users get SMS only, and a signing domain can belong to a mail vendor such as SendGrid.

**Tainted funds.** A seller can receive stolen money and have an account frozen. Nothing here solves that.

**Counterparties see each other.** Bank rails show the payer to the payee.

**The crypto leg is public.** Confidential Intents would hide balances from the public, but its own docs describe it as access control, not cryptography.

**Regulation.** P2P fiat exchange is regulated in many countries. This is a testnet prototype with fictional banks. Moving real money needs legal review, country by country.

**Availability.** OutLayer, NEAR AI and RPC providers can all deny service. Funds stay safe, and an unproven order expires back to the seller.

## Locking the release

After the final enclave version is published, `blindteller.testnet` can remove its access keys. Then nobody, including us, can add a project version or rotate the contract's enclave keys. Anyone can check this with an access key list. Until that happens, the owner is trusted not to swap the enclave.
