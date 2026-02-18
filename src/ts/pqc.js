"use strict";
// src/ts/pqc.ts
Object.defineProperty(exports, "__esModule", { value: true });
exports.fromHex = exports.toHex = void 0;
exports.generateKeypair = generateKeypair;
exports.encapsulate = encapsulate;
exports.decapsulate = decapsulate;
exports.generateSigningKeypair = generateSigningKeypair;
exports.sign = sign;
exports.verify = verify;
const ml_kem_js_1 = require("@noble/post-quantum/ml-kem.js");
const ml_dsa_js_1 = require("@noble/post-quantum/ml-dsa.js");
const utils_js_1 = require("@noble/post-quantum/utils.js");
// Helper Functions
const toHex = (bytes) => Buffer.from(bytes).toString('hex');
exports.toHex = toHex;
const fromHex = (hex) => new Uint8Array(Buffer.from(hex, 'hex'));
exports.fromHex = fromHex;
const KEM = {
    ml_kem768: ml_kem_js_1.ml_kem768,
    ml_kem1024: ml_kem_js_1.ml_kem1024,
};
const DSA = {
    ml_dsa65: ml_dsa_js_1.ml_dsa65,
    ml_dsa87: ml_dsa_js_1.ml_dsa87,
};
/**
 * Generates an ML-KEM keypair.
 * @param level The security level (ml_kem768 or ml_kem1024).
 * @returns An object containing the publicKey and secretKey.
 */
function generateKeypair(level = 'ml_kem768') {
    const seed = (0, utils_js_1.randomBytes)(64);
    return KEM[level].keygen(seed);
}
/**
 * Encapsulates a shared secret using a public key.
 * @param publicKey The recipient's public key.
 * @param level The security level.
 * @returns An object with the ciphertext and the shared secret.
 */
function encapsulate(publicKey, level = 'ml_kem768') {
    return KEM[level].encapsulate(publicKey);
}
/**
 * Decapsulates a ciphertext to retrieve the shared secret.
 * @param cipherText The ciphertext received.
 * @param secretKey The recipient's secret key.
 * @param level The security level.
 * @returns The shared secret.
 */
function decapsulate(cipherText, secretKey, level = 'ml_kem768') {
    return KEM[level].decapsulate(cipherText, secretKey);
}
/**
 * Generates an ML-DSA signing keypair.
 * @param level The security level (ml_dsa65 or ml_dsa87).
 * @returns An object containing the publicKey and secretKey.
 */
function generateSigningKeypair(level = 'ml_dsa65') {
    const seed = (0, utils_js_1.randomBytes)(32);
    return DSA[level].keygen(seed);
}
/**
 * Signs a message using a secret key.
 * @param message The message to sign (string or Uint8Array).
 * @param secretKey The signer's secret key.
 * @param level The security level.
 * @returns The signature as a Uint8Array.
 */
function sign(message, secretKey, level = 'ml_dsa65') {
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
function verify(signature, message, publicKey, level = 'ml_dsa65') {
    const messageBytes = typeof message === 'string' ? new TextEncoder().encode(message) : message;
    return DSA[level].verify(signature, messageBytes, publicKey);
}
