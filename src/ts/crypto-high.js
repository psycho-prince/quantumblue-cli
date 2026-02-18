"use strict";
// src/ts/crypto-high.ts
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateHybridKeypair = generateHybridKeypair;
exports.encrypt = encrypt;
exports.decrypt = decrypt;
exports.fileEncrypt = fileEncrypt;
exports.fileDecrypt = fileDecrypt;
const fs_1 = require("fs");
const hkdf_js_1 = require("@noble/hashes/hkdf.js");
const nobleHashesSha2 = __importStar(require("@noble/hashes/sha2.js"));
const aes_js_1 = require("@noble/ciphers/aes.js");
const utils_js_1 = require("@noble/ciphers/utils.js");
const hybrid_js_1 = require("@noble/post-quantum/hybrid.js");
const pqc_1 = require("./pqc"); // Assuming pqc.ts is in the same directory
// --- Constants and Types ---
const HKDF_INFO = new TextEncoder().encode('quantumblue-hybrid-v1'); // Corrected type
const KEY_SIZE = 32; // 32 bytes for AES-256
const IV_SIZE = 12; // 12 bytes for AES-GCM nonce
const TAG_LENGTH = 16; // 16 bytes for AES-GCM tag
// --- Core Cryptographic API ---
/**
 * Generates a hybrid ML-KEM-768 + X25519 keypair.
 * Keys are returned as hex strings.
 */
function generateHybridKeypair() {
    const { publicKey, secretKey } = hybrid_js_1.ml_kem768_x25519.keygen();
    return {
        publicKey: (0, pqc_1.toHex)(publicKey),
        secretKey: (0, pqc_1.toHex)(secretKey),
    };
}
/**
 * Encrypts data for a recipient using a hybrid PQC scheme.
 * @param data The plaintext data to encrypt (string or Uint8Array).
 * @param recipientPublicKeyHex The recipient's public key (hex string).
 * @returns The encrypted object containing all necessary components for decryption.
 */
function encrypt(data, recipientPublicKeyHex) {
    // 1. Perform hybrid KEM encapsulation to get a shared secret
    const recipientPublicKey = (0, pqc_1.fromHex)(recipientPublicKeyHex);
    const { sharedSecret: kemSharedSecret, cipherText: kemCiphertext } = hybrid_js_1.ml_kem768_x25519.encapsulate(recipientPublicKey);
    // 2. Derive a symmetric key using HKDF-SHA512
    const salt = (0, utils_js_1.randomBytes)(32); // Use a random salt for HKDF
    const derivedKey = (0, hkdf_js_1.hkdf)(nobleHashesSha2.sha512, kemSharedSecret, salt, HKDF_INFO, KEY_SIZE);
    // 3. Encrypt the data with AES-256-GCM
    const iv = (0, utils_js_1.randomBytes)(IV_SIZE);
    const dataBytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    const aes = (0, aes_js_1.gcm)(derivedKey, iv);
    const combinedCiphertextTag = aes.encrypt(dataBytes);
    const ciphertext = combinedCiphertextTag.subarray(0, combinedCiphertextTag.length - TAG_LENGTH);
    const tag = combinedCiphertextTag.subarray(combinedCiphertextTag.length - TAG_LENGTH);
    // 4. Return all parts needed for decryption, hex-encoded
    // The salt is combined with the KEM ciphertext for simplicity.
    return {
        kemCiphertext: (0, pqc_1.toHex)(new Uint8Array([...salt, ...kemCiphertext])),
        iv: (0, pqc_1.toHex)(iv),
        ciphertext: (0, pqc_1.toHex)(ciphertext),
        tag: (0, pqc_1.toHex)(tag),
    };
}
/**
 * Decrypts data that was encrypted with the hybrid PQC scheme.
 * @param encryptedObject The object containing ciphertext, IV, tag, etc.
 * @param privateKeyHex The recipient's private key (hex string).
 * @returns The decrypted plaintext as a Uint8Array.
 * @throws Error if the authentication tag is invalid.
 */
function decrypt(encryptedObject, privateKeyHex) {
    // 1. Decode all hex components
    const privateKey = (0, pqc_1.fromHex)(privateKeyHex);
    const { kemCiphertext: combinedKemCiphertext, iv, ciphertext, tag } = encryptedObject;
    const combinedKemBytes = (0, pqc_1.fromHex)(combinedKemCiphertext);
    const salt = combinedKemBytes.slice(0, 32);
    const kemCiphertext = combinedKemBytes.slice(32);
    // 2. Perform hybrid KEM decapsulation to get the shared secret
    const kemSharedSecret = hybrid_js_1.ml_kem768_x25519.decapsulate(kemCiphertext, privateKey);
    // 3. Re-derive the same symmetric key using HKDF-SHA512
    const derivedKey = (0, hkdf_js_1.hkdf)(nobleHashesSha2.sha512, kemSharedSecret, salt, HKDF_INFO, KEY_SIZE);
    // 4. Decrypt the data with AES-256-GCM and verify the authentication tag
    const combinedCiphertextTag = (0, utils_js_1.concatBytes)((0, pqc_1.fromHex)(ciphertext), (0, pqc_1.fromHex)(tag));
    const plaintext = (0, aes_js_1.gcm)(derivedKey, (0, pqc_1.fromHex)(iv)).decrypt(combinedCiphertextTag);
    return plaintext;
}
// --- File-Based API ---
/**
 * Encrypts a file for a recipient and saves it to a new file.
 * @param inputPath Path to the plaintext file.
 * @param outputPath Path to write the encrypted file.
 * @param recipientPublicKeyHex The recipient's public key (hex string).
 */
async function fileEncrypt(inputPath, outputPath, recipientPublicKeyHex) {
    const plaintext = await fs_1.promises.readFile(inputPath);
    const encryptedObject = encrypt(plaintext, recipientPublicKeyHex);
    await fs_1.promises.writeFile(outputPath, JSON.stringify(encryptedObject, null, 2));
}
/**
 * Decrypts a file and saves the plaintext to a new file.
 * @param inputPath Path to the encrypted file.
 * @param outputPath Path to write the decrypted plaintext file.
 * @param privateKeyHex The recipient's private key (hex string).
 */
async function fileDecrypt(inputPath, outputPath, privateKeyHex) {
    const encryptedFileContent = await fs_1.promises.readFile(inputPath, 'utf-8');
    const encryptedObject = JSON.parse(encryptedFileContent);
    const plaintext = decrypt(encryptedObject, privateKeyHex);
    await fs_1.promises.writeFile(outputPath, plaintext);
}
