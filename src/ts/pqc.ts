// src/ts/pqc.ts

import { ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { randomBytes } from '@noble/post-quantum/utils.js';

// Helper Functions
export const toHex = (bytes: Uint8Array): string =>
  Buffer.from(bytes).toString('hex');

export const fromHex = (hex: string): Uint8Array =>
  new Uint8Array(Buffer.from(hex, 'hex'));

// KEM Types
type KemLevel = 'ml_kem768' | 'ml_kem1024';
const KEM = {
  ml_kem768: ml_kem768,
  ml_kem1024: ml_kem1024,
};

// DSA Types
type DsaLevel = 'ml_dsa65' | 'ml_dsa87';
const DSA = {
  ml_dsa65: ml_dsa65,
  ml_dsa87: ml_dsa87,
};

/**
 * Generates an ML-KEM keypair.
 * @param level The security level (ml_kem768 or ml_kem1024).
 * @returns An object containing the publicKey and secretKey.
 */
export function generateKeypair(level: KemLevel = 'ml_kem768') {
  const seed = randomBytes(64);
  return KEM[level].keygen(seed);
}

/**
 * Encapsulates a shared secret using a public key.
 * @param publicKey The recipient's public key.
 * @param level The security level.
 * @returns An object with the ciphertext and the shared secret.
 */
export function encapsulate(
  publicKey: Uint8Array,
  level: KemLevel = 'ml_kem768'
) {
  return KEM[level].encapsulate(publicKey);
}

/**
 * Decapsulates a ciphertext to retrieve the shared secret.
 * @param cipherText The ciphertext received.
 * @param secretKey The recipient's secret key.
 * @param level The security level.
 * @returns The shared secret.
 */
export function decapsulate(
  cipherText: Uint8Array,
  secretKey: Uint8Array,
  level: KemLevel = 'ml_kem768'
) {
  return KEM[level].decapsulate(cipherText, secretKey);
}

/**
 * Generates an ML-DSA signing keypair.
 * @param level The security level (ml_dsa65 or ml_dsa87).
 * @returns An object containing the publicKey and secretKey.
 */
export function generateSigningKeypair(level: DsaLevel = 'ml_dsa65') {
  const seed = randomBytes(32);
  return DSA[level].keygen(seed);
}

/**
 * Signs a message using a secret key.
 * @param message The message to sign (string or Uint8Array).
 * @param secretKey The signer's secret key.
 * @param level The security level.
 * @returns The signature as a Uint8Array.
 */
export function sign(
  message: Uint8Array | string,
  secretKey: Uint8Array,
  level: DsaLevel = 'ml_dsa65'
) {
  const messageBytes = typeof message === 'string' ? new TextEncoder().encode(message) : message;
  return DSA[level].sign(messageBytes, secretKey);
}

/**
 * Verifies a signature.
 * @param signature The signature to verify.
 * @param message The original message.
 * @param publicKey The signer's public key.
 * @param level The security level.
 * @returns True if the signature is valid, false otherwise.
 */
export function verify(
  signature: Uint8Array,
  message: Uint8Array | string,
  publicKey: Uint8Array,
  level: DsaLevel = 'ml_dsa65'
) {
  const messageBytes = typeof message === 'string' ? new TextEncoder().encode(message) : message;
  return DSA[level].verify(signature, messageBytes, publicKey);
}
