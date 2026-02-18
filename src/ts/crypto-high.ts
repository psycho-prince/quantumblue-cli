// src/ts/crypto-high.ts

import { promises as fs } from 'fs';
import { hkdf } from '@noble/hashes/hkdf.js';
import * as nobleHashesSha2 from '@noble/hashes/sha2.js';
import { gcm } from '@noble/ciphers/aes.js';
import { randomBytes, concatBytes } from '@noble/ciphers/utils.js';
import { ml_kem768_x25519 } from '@noble/post-quantum/hybrid.js';
import { toHex, fromHex } from './pqc.js'; // Assuming pqc.ts is in the same directory

// --- Constants and Types ---

const HKDF_INFO = new TextEncoder().encode('quantumblue-hybrid-v1'); // Corrected type
const KEY_SIZE = 32; // 32 bytes for AES-256
const IV_SIZE = 12; // 12 bytes for AES-GCM nonce
const TAG_LENGTH = 16; // 16 bytes for AES-GCM tag

export interface EncryptedObject {
  kemCiphertext: string; // hex
  iv: string; // hex
  ciphertext: string; // hex
  tag: string; // hex
}

// --- Core Cryptographic API ---

/**
 * Generates a hybrid ML-KEM-768 + X25519 keypair.
 * Keys are returned as hex strings.
 */
export function generateHybridKeypair(): { publicKey: string; secretKey: string } {
  const { publicKey, secretKey } = ml_kem768_x25519.keygen();
  return {
    publicKey: toHex(publicKey),
    secretKey: toHex(secretKey),
  };
}

/**
 * Encrypts data for a recipient using a hybrid PQC scheme.
 * @param data The plaintext data to encrypt (string or Uint8Array).
 * @param recipientPublicKeyHex The recipient's public key (hex string).
 * @returns The encrypted object containing all necessary components for decryption.
 */
export async function encrypt( // Marked as async
  data: Uint8Array | string,
  recipientPublicKeyHex: string
): Promise<EncryptedObject> { // Return type also becomes Promise
  // 1. Perform hybrid KEM encapsulation to get a shared secret
  const recipientPublicKey = fromHex(recipientPublicKeyHex);
  const { sharedSecret: kemSharedSecret, cipherText: kemCiphertext } =
    ml_kem768_x25519.encapsulate(recipientPublicKey);

  // 2. Derive a symmetric key using HKDF-SHA512
  const salt = randomBytes(32); // Use a random salt for HKDF
  const derivedKey = hkdf(nobleHashesSha2.sha512, kemSharedSecret, salt, HKDF_INFO, KEY_SIZE);

  // 3. Encrypt the data with AES-256-GCM
  const iv = randomBytes(IV_SIZE);
  const dataBytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const aes = gcm(derivedKey, iv);
  const combinedCiphertextTag = await aes.encrypt(dataBytes); // Await the promise
  const ciphertext = combinedCiphertextTag.subarray(0, combinedCiphertextTag.length - TAG_LENGTH);
  const tag = combinedCiphertextTag.subarray(combinedCiphertextTag.length - TAG_LENGTH);

  // 4. Return all parts needed for decryption, hex-encoded
  // The salt is combined with the KEM ciphertext for simplicity.
  return {
    kemCiphertext: toHex(new Uint8Array([...salt, ...kemCiphertext])),
    iv: toHex(iv),
    ciphertext: toHex(ciphertext),
    tag: toHex(tag),
  };
}

/**
 * Decrypts data that was encrypted with the hybrid PQC scheme.
 * @param encryptedObject The object containing ciphertext, IV, tag, etc.
 * @param privateKeyHex The recipient's private key (hex string).
 * @returns The decrypted plaintext as a Uint8Array.
 * @throws Error if the authentication tag is invalid.
 */
export async function decrypt( // Marked as async
  encryptedObject: EncryptedObject,
  privateKeyHex: string
): Promise<Uint8Array> { // Return type also becomes Promise
  // 1. Decode all hex components
  const privateKey = fromHex(privateKeyHex);
  const { kemCiphertext: combinedKemCiphertext, iv, ciphertext, tag } = encryptedObject;
  const combinedKemBytes = fromHex(combinedKemCiphertext);
  const salt = combinedKemBytes.slice(0, 32);
  const kemCiphertext = combinedKemBytes.slice(32);

  // 2. Perform hybrid KEM decapsulation to get the shared secret
  const kemSharedSecret = ml_kem768_x25519.decapsulate(kemCiphertext, privateKey);

  // 3. Re-derive the same symmetric key using HKDF-SHA512
  const derivedKey = hkdf(nobleHashesSha2.sha512, kemSharedSecret, salt, HKDF_INFO, KEY_SIZE);

  // 4. Decrypt the data with AES-256-GCM and verify the authentication tag
  const combinedCiphertextTag = concatBytes(fromHex(ciphertext), fromHex(tag));
  const plaintext = await gcm(derivedKey, fromHex(iv)).decrypt(combinedCiphertextTag); // Await the promise

  return plaintext;
}

// --- File-Based API ---

/**
 * Encrypts a file for a recipient and saves it to a new file.
 * @param inputPath Path to the plaintext file.
 * @param outputPath Path to write the encrypted file.
 * @param recipientPublicKeyHex The recipient's public key (hex string).
 */
export async function fileEncrypt(
  inputPath: string,
  outputPath: string,
  recipientPublicKeyHex: string
): Promise<void> {
  const plaintext = await fs.readFile(inputPath);
  const encryptedObject = encrypt(plaintext, recipientPublicKeyHex);
  await fs.writeFile(outputPath, JSON.stringify(encryptedObject, null, 2));
}

/**
 * Decrypts a file and saves the plaintext to a new file.
 * @param inputPath Path to the encrypted file.
 * @param outputPath Path to write the decrypted plaintext file.
 * @param privateKeyHex The recipient's private key (hex string).
 */
export async function fileDecrypt(
  inputPath: string,
  outputPath: string,
  privateKeyHex: string
): Promise<void> {
  const encryptedFileContent = await fs.readFile(inputPath, 'utf-8');
  const encryptedObject: EncryptedObject = JSON.parse(encryptedFileContent);
  const plaintext = await decrypt(encryptedObject, privateKeyHex); // Await the promise
  await fs.writeFile(outputPath, plaintext);
}
