// test-high.ts
import {
  generateHybridKeypair,
  encryptString,
  decryptString,
} from './src/ts/high-crypto.ts'; // Import from compiled JS

async function runTest() {
  console.log('--- Starting Hybrid PQC Encryption Test ---');

  try {
    // 1. Generate Keypair
    console.log('Step 1: Generating key pair...');
    const { publicKeyHex, privateKeyHex } = await generateHybridKeypair();
    console.log('  - Key pair generated.');

    // 2. Encrypt
    const plaintext = 'Quantum secure test 2026';
    console.log(`Step 2: Encrypting plaintext: "${plaintext}"`);
    const encrypted = await encryptString(plaintext, publicKeyHex);
    console.log('  - Encryption successful.');

    // 3. Decrypt
    console.log('Step 3: Decrypting ciphertext...');
    const decrypted = await decryptString(
      encrypted,
      privateKeyHex,
      encrypted.kemCiphertextHex
    );
    console.log(`  - Decrypted text: "${decrypted}"`);

    // 4. Verify
    console.log('Step 4: Verifying result...');
    if (plaintext === decrypted) {
      console.log('✅ SUCCESS: Decrypted text matches original plaintext.');
    } else {
      throw new Error('Verification failed: Mismatch in plaintext.');
    }
  } catch (error) {
    console.error('❌ FAILED:', (error as Error).message);
    process.exit(1);
  }

  console.log('--- Test Completed Successfully ---');
}

runTest();
