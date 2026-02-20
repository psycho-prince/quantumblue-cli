// src/ts/high-crypto.ts
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

/**
 * Returns the ML-DSA instance for a given security level.
 */
function getMLDSA(level: string) {
  if (level === 'mldsa87') return ml_dsa87;
  return ml_dsa65; // Default
}

/**
 * Generates an ML-DSA signing keypair.
 */
export async function generateSigningKeypair(level: string = 'mldsa65') {
  const dsa = getMLDSA(level);
  const keys = dsa.keygen();
  return {
    publicKeyHex: bytesToHex(keys.publicKey),
    privateKeyHex: bytesToHex(keys.secretKey),
  };
}

/**
 * Signs a message using ML-DSA.
 */
export async function signMessage(message: string, privateKeyHex: string, level: string = 'mldsa65') {
  const dsa = getMLDSA(level);
  const sig = dsa.sign(encoder.encode(message), hexToBytes(privateKeyHex));
  return bytesToHex(sig);
}

/**
 * Verifies an ML-DSA signature.
 */
export async function verifySignature(signatureHex: string, message: string, publicKeyHex: string, level: string = 'mldsa65') {
  const dsa = getMLDSA(level);
  return dsa.verify(hexToBytes(signatureHex), encoder.encode(message), hexToBytes(publicKeyHex));
}

/**
 * Generates a hybrid post-quantum/classical keypair (ML-KEM-768 & X25519).
 * @returns {Promise<{ publicKeyHex: string, privateKeyHex: string }>} The public and private keys as hex strings.
 */
export async function generateHybridKeypair(): Promise<{ publicKeyHex: string, privateKeyHex: string }> {
  try {
    const keyPair = ml_kem768_x25519.keygen();
    return {
      publicKeyHex: bytesToHex(keyPair.publicKey),
      privateKeyHex: bytesToHex(keyPair.secretKey),
    };
  } catch (error) {
    console.error('Keypair generation failed:', error);
    throw new Error('Failed to generate hybrid keypair.');
  }
}

/**
 * Encrypts a string using a hybrid scheme (AES-256-GCM + ML-KEM-768/X25519).
 * @param {string} plaintext The string to encrypt.
 * @param {string} recipientPubKeyHex The recipient's public key in hex format.
 * @returns {Promise<{ ivHex: string, ciphertextHex: string, tagHex: string, kemCiphertextHex: string }>} The encrypted components.
 */
export async function encryptString(plaintext: string, recipientPubKeyHex: string) {
  try {
    const recipientPubKey = hexToBytes(recipientPubKeyHex);
    const { sharedSecret, cipherText } = ml_kem768_x25519.encapsulate(recipientPubKey);

    const derivedKey = hkdf(sha512, sharedSecret, undefined, HKDF_INFO, 32);
    const iv = randomBytes(16);
    const plaintextBytes = encoder.encode(plaintext);
    
    const aes = gcm(derivedKey, iv);
    const ciphertext = await aes.encrypt(plaintextBytes); // Await the encrypt result
    
    return {
      ivHex: bytesToHex(iv),
      ciphertextHex: bytesToHex(ciphertext.slice(0, -16)),
      tagHex: bytesToHex(ciphertext.slice(-16)),
      kemCiphertextHex: bytesToHex(cipherText),
    };
  } catch (error) {
    console.error('Encryption failed:', error);
    throw new Error('Failed to encrypt string.');
  }
}

/**
 * Decrypts a string using a hybrid scheme.
 * @param {{ ivHex: string, ciphertextHex: string, tagHex: string }} encrypted The encrypted components.
 * @param {string} privateKeyHex The user's private key in hex format.
 * @param {string} kemCiphertextHex The KEM-encapsulated key from the encryption step.
 * @returns {Promise<string>} The decrypted plaintext string.
 */
export async function decryptString(
  encrypted: { ivHex: string, ciphertextHex: string, tagHex: string },
  privateKeyHex: string,
  kemCiphertextHex: string
): Promise<string> {
  try {
    const privateKey = hexToBytes(privateKeyHex);
    const kemCiphertext = hexToBytes(kemCiphertextHex);
    
    const sharedSecret = ml_kem768_x25519.decapsulate(kemCiphertext, privateKey);
    
    const derivedKey = hkdf(sha512, sharedSecret, undefined, HKDF_INFO, 32);
    const iv = hexToBytes(encrypted.ivHex);
    const ciphertext = hexToBytes(encrypted.ciphertextHex);
    const tag = hexToBytes(encrypted.tagHex);

    const taggedCiphertext = new Uint8Array(ciphertext.length + tag.length);
    taggedCiphertext.set(ciphertext);
    taggedCiphertext.set(tag, ciphertext.length);

    const aes = gcm(derivedKey, iv);
    const decryptedBytes = await aes.decrypt(taggedCiphertext); // Await the decrypt result

    return decoder.decode(decryptedBytes);
  } catch (error) {
    console.error('Decryption failed:', error);
    throw new Error('Failed to decrypt string. Check keys and input data.');
  }
}
