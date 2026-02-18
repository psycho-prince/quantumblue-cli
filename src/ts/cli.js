"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const commander_1 = require("commander");
const high_crypto_1 = require("./high-crypto"); // Relative import
// Helper to handle async operations and exit gracefully
const wrapAsync = (fn) => (...args) => {
    fn(...args).catch((err) => {
        console.error(`Error: ${err.message}`);
        process.exit(1);
    });
};
commander_1.program.version('1.0.0').description('QuantumBlue CLI for Hybrid Post-Quantum Cryptography');
commander_1.program
    .command('generate-keypair')
    .description('Generates a new hybrid KEM key pair.')
    .action(wrapAsync(async () => {
    console.log('Generating key pair...');
    const { publicKeyHex, privateKeyHex } = await (0, high_crypto_1.generateHybridKeypair)();
    console.log('Public Key (Hex):', publicKeyHex);
    console.log('Private Key (Hex):', privateKeyHex);
}));
commander_1.program
    .command('encrypt <plaintext> <recipientPubKeyHex>')
    .description('Encrypts a string for a recipient using their public key.')
    .action(wrapAsync(async (plaintext, recipientPubKeyHex) => {
    console.log('Encrypting string...');
    const result = await (0, high_crypto_1.encryptString)(plaintext, recipientPubKeyHex);
    console.log('Encryption Result:');
    console.log('  IV (Hex):', result.ivHex);
    console.log('  Ciphertext (Hex):', result.ciphertextHex);
    console.log('  Tag (Hex):', result.tagHex);
    console.log('  KEM Encapsulation (Hex):', result.kemCiphertextHex); // Now included
}));
commander_1.program
    .command('decrypt <ivHex> <ciphertextHex> <tagHex> <privateKeyHex> <kemCiphertextHex>')
    .description('Decrypts an encrypted string using a private key and KEM encapsulation.')
    .action(wrapAsync(async (ivHex, ciphertextHex, tagHex, privateKeyHex, kemCiphertextHex) => {
    console.log('Decrypting string...');
    const encrypted = { ivHex, ciphertextHex, tagHex };
    const decryptedText = await (0, high_crypto_1.decryptString)(encrypted, privateKeyHex, kemCiphertextHex);
    console.log('Decrypted Text:', decryptedText);
}));
commander_1.program.parse(process.argv);
