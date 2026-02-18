"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateHybridKeypair = generateHybridKeypair;
exports.encryptString = encryptString;
exports.decryptString = decryptString;
const hybrid_js_1 = require("@noble/post-quantum/hybrid.js");
const hkdf_1 = require("@noble/hashes/hkdf");
const sha512_1 = require("@noble/hashes/sha512");
const aes_1 = require("@noble/ciphers/aes");
const utils_js_1 = require("@noble/post-quantum/utils.js");
const util_1 = require("util"); // Node.js built-in
const encoder = new util_1.TextEncoder();
const decoder = new util_1.TextDecoder();
const HKDF_INFO = encoder.encode("quantumblue-hybrid-v1");
const IV_LENGTH = 12; // GCM recommended IV length
/**
 * Generates a hybrid post-quantum key pair (ML-KEM-768 + X25519).
 * @returns {Promise<{ publicKeyHex: string, privateKeyHex: string }>} A promise that resolves to the key pair.
 */
async function generateHybridKeypair() {
    // `keygen` returns an object with publicKey and secretKey (private key)
    const keyPair = hybrid_js_1.ml_kem768_x25519.keygen(); // No seed provided, uses random
    return {
        publicKeyHex: Buffer.from(keyPair.publicKey).toString('hex'),
        privateKeyHex: Buffer.from(keyPair.secretKey).toString('hex'), // Use secretKey as privateKey
    };
}
/**
 * Encrypts a plaintext string using hybrid post-quantum encryption (ML-KEM-768 + X25519 + AES-256-GCM).
 * @param plaintext The string to encrypt.
 * @param recipientPubHex The recipient's public key in hex format.
 * @returns {Promise<{ ivHex: string, ciphertextHex: string, tagHex: string, kemCiphertextHex: string }>} A promise that resolves to the encrypted data.
 */
async function encryptString(plaintext, recipientPubHex) {
    try {
        const recipientPublicKey = Buffer.from(recipientPubHex, 'hex');
        // Encapsulate the shared secret using the recipient's public key
        const { sharedSecret: senderSharedSecret, cipherText: kemCiphertext } = // Renamed 'encapsulation' to 'cipherText' as per docs
         hybrid_js_1.ml_kem768_x25519.encapsulate(recipientPublicKey); // No await needed, it's synchronous
        // Derive a symmetric key using HKDF-SHA512
        const derivedKey = await (0, hkdf_1.hkdf)(sha512_1.sha512, senderSharedSecret, kemCiphertext, HKDF_INFO, 32); // 32 bytes for AES-256
        const iv = (0, utils_js_1.randomBytes)(IV_LENGTH);
        const plaintextBytes = encoder.encode(plaintext);
        const { ciphertext, tag } = await (0, aes_1.gcm)(derivedKey, iv).encrypt(plaintextBytes);
        return {
            ivHex: Buffer.from(iv).toString('hex'),
            ciphertextHex: Buffer.from(ciphertext).toString('hex'),
            tagHex: Buffer.from(tag).toString('hex'),
            kemCiphertextHex: Buffer.from(kemCiphertext).toString('hex'), // Include KEM encapsulation for decryption
        };
    }
    catch (error) {
        console.error("Encryption failed:", error);
        throw new Error("Failed to encrypt string.");
    }
}
/**
 * Decrypts an encrypted string using hybrid post-quantum encryption.
 * @param encrypted The encrypted data including IV, ciphertext, and tag in hex format, and the KEM encapsulation.
 * @param privateKeyHex The recipient's private key in hex format.
 * @param kemCiphertextHex The KEM encapsulation (ciphertext from sender) in hex format.
 * @returns {Promise<string>} A promise that resolves to the decrypted plaintext string.
 */
async function decryptString(encrypted, privateKeyHex, kemCiphertextHex) {
    try {
        const privateKey = Buffer.from(privateKeyHex, 'hex');
        const kemCiphertext = Buffer.from(kemCiphertextHex, 'hex');
        const iv = Buffer.from(encrypted.ivHex, 'hex');
        const ciphertext = Buffer.from(encrypted.ciphertextHex, 'hex');
        const tag = Buffer.from(encrypted.tagHex, 'hex');
        // Decapsulate the shared secret using the recipient's private key and the KEM ciphertext
        const recipientSharedSecret = hybrid_js_1.ml_kem768_x25519.decapsulate(kemCiphertext, privateKey); // Order of args changed, also synchronous
        // Derive the symmetric key using HKDF-SHA512 (must use the same salt and info as encryption)
        const derivedKey = await (0, hkdf_1.hkdf)(sha512_1.sha512, recipientSharedSecret, kemCiphertext, HKDF_INFO, 32);
        const decryptedBytes = await (0, aes_1.gcm)(derivedKey, iv).decrypt(ciphertext, tag);
        return decoder.decode(decryptedBytes);
    }
    catch (error) {
        console.error("Decryption failed:", error);
        throw new Error("Failed to decrypt string.");
    }
}
