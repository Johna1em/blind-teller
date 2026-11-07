// Sealing, matching enclave/src/seal.rs byte for byte. An email is encrypted here
// in the browser, so it reaches the enclave without anyone in between reading it.
//
// Wire format, base64: 0x01 | ephemeral_public(32) | nonce(12) | ciphertext+tag

import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { concat, fromBase64, randomBytes, toBase64, utf8 } from './bytes';

const VERSION = 1;
const INFO = utf8('blind-teller/v1/seal');

function derive(shared: Uint8Array, ephemeral: Uint8Array, recipient: Uint8Array): Uint8Array {
  return hkdf(sha256, shared, concat(ephemeral, recipient), INFO, 32);
}

export function publicOf(secret: Uint8Array): Uint8Array {
  return x25519.getPublicKey(secret);
}

/** `entropy` is for test vectors. Leave it out and fresh randomness is used. */
export function seal(recipient: Uint8Array, plain: Uint8Array, aad: string, entropy?: Uint8Array): string {
  const material = entropy ?? randomBytes(44);
  const ephemeralSecret = material.subarray(0, 32);
  const nonce = material.subarray(32, 44);
  const ephemeral = x25519.getPublicKey(ephemeralSecret);
  const key = derive(x25519.getSharedSecret(ephemeralSecret, recipient), ephemeral, recipient);
  const ciphertext = chacha20poly1305(key, nonce, utf8(aad)).encrypt(plain);
  return toBase64(concat(Uint8Array.of(VERSION), ephemeral, nonce, ciphertext));
}

export function open(secret: Uint8Array, sealed: string, aad: string): Uint8Array {
  const raw = fromBase64(sealed);
  if (raw.length < 61 || raw[0] !== VERSION) throw new Error('bad ciphertext');
  const ephemeral = raw.subarray(1, 33);
  const key = derive(x25519.getSharedSecret(secret, ephemeral), ephemeral, x25519.getPublicKey(secret));
  return chacha20poly1305(key, raw.subarray(33, 45), utf8(aad)).decrypt(raw.subarray(45));
}
