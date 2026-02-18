// src/ts/high-crypto.ts
import { ml_kem768_x25519 } from '@noble/post-quantum/hybrid.js';
import { hkdf } from '@noble/hashes/hkdf';
import { sha512 } from '@noble/hashes/sha512';
import { gcm } from '@noble/ciphers/aes';
import { randomBytes } from '@noble/post-quantum/utils.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const HKDF_INFO = 'quantumblue-hybrid-v1';

/**
 * Generates a hybrid post-quantum/classical keypair (ML-KEM-768 & X25519).
 * @returns {Promise<{ publicKeyHex: string, privateKeyHex: string }>} The public and private keys as hex strings.
 */
export async function generateHybridKeypair(): Promise<{ publicKeyHex: string, privateKeyHex: string }> {
  try {
    const keyPair = await ml_kem768_x25519.generateKeyPair();
    return {
      publicKeyHex: bytesToHex(keyPair.publicKey),
      privateKeyHex: bytesToHex(keyPair.privateKey),
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
    const { sharedSecret, kemCiphertext } = await ml_kem768_x25519.encapsulate(recipientPubKey);

    const derivedKey = hkdf(sha512, sharedSecret, undefined, HKDF_INFO, 32);
    const iv = randomBytes(16);
    const plaintextBytes = encoder.encode(plaintext);
    
    const aes = gcm(derivedKey, iv);
    const ciphertext = aes.encrypt(plaintextBytes);
    
    return {
      ivHex: bytesToHex(iv),
      ciphertextHex: bytesToHex(ciphertext.slice(0, -16)),
      tagHex: bytesToHex(ciphertext.slice(-16)),
      kemCiphertextHex: bytesToHex(kemCiphertext),
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
    
    const sharedSecret = await ml_kem768_x25519.decapsulate(kemCiphertext, privateKey);
    
    const derivedKey = hkdf(sha512, sharedSecret, undefined, HKDF_INFO, 32);
    const iv = hexToBytes(encrypted.ivHex);
    const ciphertext = hexToBytes(encrypted.ciphertextHex);
    const tag = hexToBytes(encrypted.tagHex);

    const taggedCiphertext = new Uint8Array(ciphertext.length + tag.length);
    taggedCiphertext.set(ciphertext);
    taggedCiphertext.set(tag, ciphertext.length);

    const aes = gcm(derivedKey, iv);
    const decryptedBytes = aes.decrypt(taggedCiphertext);

    return decoder.decode(decryptedBytes);
  } catch (error) {
    console.error('Decryption failed:', error);
    throw new Error('Failed to decrypt string. Check keys and input data.');
  }
}
