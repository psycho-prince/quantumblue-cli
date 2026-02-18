"use strict";
// test-high.ts
Object.defineProperty(exports, "__esModule", { value: true });
const fs_1 = require("fs");
const crypto_high_1 = require("./src/ts/crypto-high");
const TEMP_INPUT_FILE = 'temp_input.txt';
const TEMP_ENCRYPTED_FILE = 'temp_encrypted.json';
const TEMP_DECRYPTED_FILE = 'temp_decrypted.txt';
console.log('--- Testing High-Level Hybrid Post-Quantum Crypto ---');
async function runTests() {
    const decoder = new TextDecoder();
    // Test 1: Hybrid Keypair Generation
    console.log(''); // Added for newline
    console.log('[1] Testing Hybrid Keypair Generation...');
    try {
        const { publicKey, secretKey } = (0, crypto_high_1.generateHybridKeypair)();
        console.log('  - Generated hybrid keypair.');
        console.log(`    - Public Key (first 16 hex): ${publicKey.slice(0, 32)}...`);
        console.log(`    - Secret Key (first 16 hex): ${secretKey.slice(0, 32)}...`);
        if (!publicKey || !secretKey) {
            throw new Error('Key generation failed.');
        }
        console.log('  - Keypair generation: ✅ SUCCESS');
    }
    catch (e) {
        console.error('  - Keypair generation: ❌ FAILURE', e);
        process.exit(1);
    }
    // Generate a keypair for further tests
    const { publicKey: recipientPublicKeyHex, secretKey: recipientSecretKeyHex } = (0, crypto_high_1.generateHybridKeypair)();
    // Test 2: String Encrypt/Decrypt Roundtrip
    console.log(''); // Added for newline
    console.log('[2] Testing String Encrypt/Decrypt Roundtrip...');
    try {
        const originalMessage = 'This is a quantum-secure test message!';
        console.log(`  - Original message: "${originalMessage}"`);
        const encryptedData = (0, crypto_high_1.encrypt)(originalMessage, recipientPublicKeyHex);
        console.log('  - Message encrypted.');
        console.log(`    - Ciphertext (first 16 hex): ${encryptedData.ciphertext.slice(0, 32)}...`);
        console.log(`    - IV (first 16 hex):         ${encryptedData.iv.slice(0, 32)}...`);
        console.log(`    - Tag (first 16 hex):        ${encryptedData.tag.slice(0, 32)}...`);
        console.log(`    - KEM Ciphertext (first 16 hex): ${encryptedData.kemCiphertext.slice(0, 32)}...`);
        const decryptedBytes = (0, crypto_high_1.decrypt)(encryptedData, recipientSecretKeyHex);
        const decryptedMessage = decoder.decode(decryptedBytes);
        console.log(`  - Message decrypted: "${decryptedMessage}"`);
        if (originalMessage === decryptedMessage) {
            console.log('  - String encrypt/decrypt: ✅ SUCCESS');
        }
        else {
            throw new Error('Decrypted message does not match original.');
        }
    }
    catch (e) {
        console.error('  - String encrypt/decrypt: ❌ FAILURE', e);
        process.exit(1);
    }
    // Test 3: File Encrypt/Decrypt Roundtrip
    console.log(''); // Added for newline
    console.log('[3] Testing File Encrypt/Decrypt Roundtrip...');
    let cleanupFiles = false;
    try {
        const fileContent = 'This is a test file content for quantum-secure encryption.';
        await fs_1.promises.writeFile(TEMP_INPUT_FILE, fileContent);
        console.log(`  - Created temporary input file: ${TEMP_INPUT_FILE}`);
        await (0, crypto_high_1.fileEncrypt)(TEMP_INPUT_FILE, TEMP_ENCRYPTED_FILE, recipientPublicKeyHex);
        console.log(`  - Encrypted file to: ${TEMP_ENCRYPTED_FILE}`);
        await (0, crypto_high_1.fileDecrypt)(TEMP_ENCRYPTED_FILE, TEMP_DECRYPTED_FILE, recipientSecretKeyHex);
        console.log(`  - Decrypted file to: ${TEMP_DECRYPTED_FILE}`);
        const decryptedFileContent = await fs_1.promises.readFile(TEMP_DECRYPTED_FILE, 'utf-8');
        if (fileContent === decryptedFileContent) {
            console.log('  - File encrypt/decrypt: ✅ SUCCESS');
        }
        else {
            throw new Error('Decrypted file content does not match original.');
        }
        cleanupFiles = true;
    }
    catch (e) {
        console.error('  - File encrypt/decrypt: ❌ FAILURE', e);
        process.exit(1);
    }
    finally {
        if (cleanupFiles) {
            await fs_1.promises.unlink(TEMP_INPUT_FILE).catch(() => { });
            await fs_1.promises.unlink(TEMP_ENCRYPTED_FILE).catch(() => { });
            await fs_1.promises.unlink(TEMP_DECRYPTED_FILE).catch(() => { });
            console.log('  - Cleaned up temporary files.');
        }
        else {
            console.warn('  - Temporary files not cleaned up due to test failure. Please remove them manually if they exist.');
        }
    }
    console.log(''); // Added for newline
    console.log('--- High-Level PQC Tests Complete ---');
}
runTests();
