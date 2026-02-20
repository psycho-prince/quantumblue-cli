// test-pqc.ts
import { generateKeypair, encapsulate, decapsulate, generateSigningKeypair, sign, verify, toHex, } from './src/ts/pqc.js';
console.log('--- Testing Post-Quantum Cryptography Primitives ---');
// Test 1: ML-KEM-768
console.log('[1] Testing ML-KEM-768...');
try {
    // Generate keys
    const { publicKey: kemPublicKey, secretKey: kemSecretKey } = generateKeypair('ml_kem768'); // Corrected
    console.log('  - Generated ML-KEM keypair.');
    console.log(`    - Public Key (first 16 bytes): ${toHex(kemPublicKey.slice(0, 16))}...`);
    // Encapsulate to get a shared secret and ciphertext
    const { cipherText, sharedSecret: sharedSecret1 } = encapsulate(kemPublicKey, 'ml_kem768'); // Corrected
    console.log('  - Encapsulated a shared secret.');
    console.log(`    - Shared Secret 1 (first 16 bytes): ${toHex(sharedSecret1.slice(0, 16))}...`);
    console.log(`    - Ciphertext (first 16 bytes):    ${toHex(cipherText.slice(0, 16))}...`);
    // Decapsulate to get the same shared secret
    const sharedSecret2 = decapsulate(cipherText, kemSecretKey, 'ml_kem768'); // Corrected
    console.log('  - Decapsulated to retrieve shared secret.');
    console.log(`    - Shared Secret 2 (first 16 bytes): ${toHex(sharedSecret2.slice(0, 16))}...`);
    // Compare secrets
    const secretsMatch = toHex(sharedSecret1) === toHex(sharedSecret2);
    console.log(`  - Shared secrets match: ${secretsMatch ? '✅ SUCCESS' : '❌ FAILURE'}`);
    if (!secretsMatch) {
        throw new Error('ML-KEM shared secrets do not match!');
    }
}
catch (e) {
    console.error('  - ML-KEM test failed:', e);
}
// Test 2: ML-DSA-65
console.log('[2] Testing ML-DSA-65...');
try {
    const message = 'test quantum secure';
    console.log(`  - Message to sign: "${message}"`);
    // Generate keys
    const { publicKey: dsaPublicKey, secretKey: dsaSecretKey } = generateSigningKeypair('ml_dsa65'); // Corrected
    console.log('  - Generated ML-DSA keypair.');
    console.log(`    - Public Key (first 16 bytes): ${toHex(dsaPublicKey.slice(0, 16))}...`);
    // Sign the message
    const signature = sign(message, dsaSecretKey, 'ml_dsa65'); // Corrected
    console.log('  - Signed the message.');
    console.log(`    - Signature (first 16 bytes): ${toHex(signature.slice(0, 16))}...`);
    // Verify the signature
    const isVerified = verify(signature, message, dsaPublicKey, 'ml_dsa65'); // Corrected
    console.log(`  - Signature verified: ${isVerified ? '✅ SUCCESS' : '❌ FAILURE'}`);
    if (!isVerified) {
        throw new Error('ML-DSA signature verification failed!');
    }
}
catch (e) {
    console.error('  - ML-DSA test failed:', e);
}
console.log('--- PQC Tests Complete ---');
