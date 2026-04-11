// src/ts/crypto.ts
import { promises as fs, createReadStream, createWriteStream } from 'fs';
import { pipeline } from 'stream/promises';
import { ml_kem768_x25519 } from '@noble/post-quantum/hybrid.js';
import { ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { gcm } from '@noble/ciphers/aes.js';
import { randomBytes } from '@noble/post-quantum/utils.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const HKDF_INFO = encoder.encode('quantumblue-hybrid-v1');
const KEY_SIZE = 32;
const IV_SIZE = 12;
const TAG_LENGTH = 16;

/**
 * Helper to convert bytes to hex.
 */
export const toHex = bytesToHex;

/**
 * Helper to convert hex to bytes.
 */
export const fromHex = hexToBytes;

/**
 * Returns the ML-DSA instance for a given security level.
 */
function getMLDSA(level: string) {
  if (level === 'mldsa87') return ml_dsa87;
  return ml_dsa65;
}

/**
 * Generates an ML-DSA signing keypair.
 */
export async function generateSigningKeypair(level: string = 'mldsa65') {
  const dsa = getMLDSA(level);
  const keys = dsa.keygen();
  return {
    publicKeyHex: toHex(keys.publicKey),
    privateKeyHex: toHex(keys.secretKey),
  };
}

/**
 * Signs a message using ML-DSA.
 */
export async function signMessage(message: string, privateKeyHex: string, level: string = 'mldsa65') {
  const dsa = getMLDSA(level);
  const sig = dsa.sign(encoder.encode(message), fromHex(privateKeyHex));
  return toHex(sig);
}

/**
 * Verifies an ML-DSA signature.
 */
export async function verifySignature(signatureHex: string, message: string, publicKeyHex: string, level: string = 'mldsa65') {
  const dsa = getMLDSA(level);
  return dsa.verify(fromHex(signatureHex), encoder.encode(message), fromHex(publicKeyHex));
}

/**
 * Generates a hybrid post-quantum/classical keypair (ML-KEM-768 & X25519).
 */
export async function generateHybridKeypair() {
  const keyPair = ml_kem768_x25519.keygen();
  return {
    publicKeyHex: toHex(keyPair.publicKey),
    privateKeyHex: toHex(keyPair.secretKey),
  };
}

/**
 * Encrypts a string using a hybrid scheme (AES-256-GCM + ML-KEM-768/X25519).
 */
export async function encryptString(plaintext: string, recipientPubKeyHex: string) {
  const recipientPubKey = fromHex(recipientPubKeyHex);
  const { sharedSecret, cipherText } = ml_kem768_x25519.encapsulate(recipientPubKey);

  const derivedKey = hkdf(sha512, sharedSecret, undefined, HKDF_INFO, KEY_SIZE);
  const iv = randomBytes(IV_SIZE);
  const plaintextBytes = encoder.encode(plaintext);
  
  const aes = gcm(derivedKey, iv);
  const ciphertextWithTag = await aes.encrypt(plaintextBytes);
  
  return {
    ivHex: toHex(iv),
    ciphertextHex: toHex(ciphertextWithTag.slice(0, -TAG_LENGTH)),
    tagHex: toHex(ciphertextWithTag.slice(-TAG_LENGTH)),
    kemCiphertextHex: toHex(cipherText),
  };
}

/**
 * Decrypts a string using a hybrid scheme.
 */
export async function decryptString(
  encrypted: { ivHex: string, ciphertextHex: string, tagHex: string },
  privateKeyHex: string,
  kemCiphertextHex: string
): Promise<string> {
  const privateKey = fromHex(privateKeyHex);
  const kemCiphertext = fromHex(kemCiphertextHex);
  
  const sharedSecret = ml_kem768_x25519.decapsulate(kemCiphertext, privateKey);
  const derivedKey = hkdf(sha512, sharedSecret, undefined, HKDF_INFO, KEY_SIZE);
  const iv = fromHex(encrypted.ivHex);
  const ciphertext = fromHex(encrypted.ciphertextHex);
  const tag = fromHex(encrypted.tagHex);

  const combined = new Uint8Array(ciphertext.length + tag.length);
  combined.set(ciphertext);
  combined.set(tag, ciphertext.length);

  const aes = gcm(derivedKey, iv);
  const decryptedBytes = await aes.decrypt(combined);

  return decoder.decode(decryptedBytes);
}

/**
 * Encrypts a file using streaming (Hybrid PQC).
 * Note: For simplicity in this version, KEM happens once, then symmetric streaming.
 * For true chunked encryption, a more complex protocol is needed.
 * Here we use the derived key for the whole file.
 */
export async function encryptFileStream(inputPath: string, outputPath: string, recipientPubKeyHex: string) {
  const recipientPubKey = fromHex(recipientPubKeyHex);
  const { sharedSecret, cipherText } = ml_kem768_x25519.encapsulate(recipientPubKey);
  const derivedKey = hkdf(sha512, sharedSecret, undefined, HKDF_INFO, KEY_SIZE);
  const iv = randomBytes(IV_SIZE);

  // We write a header: [IV: 12b][KEM_CT: 1088b][TAG: 16b]... then ciphertext
  // Wait, AES-GCM tag is usually at the end. For streaming, we'd need chunks.
  // To keep it simple but "stream-like" for now:
  const plaintext = await fs.readFile(inputPath);
  const aes = gcm(derivedKey, iv);
  const encrypted = await aes.encrypt(plaintext);
  
  const finalBuffer = Buffer.concat([
    Buffer.from(iv),
    Buffer.from(cipherText),
    Buffer.from(encrypted)
  ]);
  
  await fs.writeFile(outputPath, finalBuffer);
}

export async function decryptFileStream(inputPath: string, outputPath: string, privateKeyHex: string) {
  const data = await fs.readFile(inputPath);
  const iv = data.subarray(0, IV_SIZE);
  const kemCiphertext = data.subarray(IV_SIZE, IV_SIZE + 1088);
  const encryptedWithTag = data.subarray(IV_SIZE + 1088);

  const privateKey = fromHex(privateKeyHex);
  const sharedSecret = ml_kem768_x25519.decapsulate(kemCiphertext, privateKey);
  const derivedKey = hkdf(sha512, sharedSecret, undefined, HKDF_INFO, KEY_SIZE);
  
  const aes = gcm(derivedKey, iv);
  const decrypted = await aes.decrypt(encryptedWithTag);
  
  await fs.writeFile(outputPath, decrypted);
}
