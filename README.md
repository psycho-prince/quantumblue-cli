# QuantumBlue CLI

Autonomous AI-powered blue team CLI for cybersecurity defense.
Features:
- Natural language commands
- Post-quantum crypto hardening (ML-KEM, ML-DSA, etc.)
- Agentic analysis, prediction, response (Web2/Web3/cloud)
- Hybrid: TypeScript CLI frontend + Python agent backend

Inspired by secure agent patterns and cybersecurity AI frameworks.

Setup:
- npm install (TS part)
- pip install -r python/requirements.txt

## Post-Quantum Cryptography

This CLI includes primitives for post-quantum cryptography (PQC) based on the NIST FIPS-203, FIPS-204, and FIPS-205 standards, powered by `@noble/post-quantum`.

### Supported Algorithms

*   **Key Encapsulation Mechanism (KEM):** ML-KEM (formerly Kyber), the successor to classic Diffie-Hellman key exchange.
    *   `ml_kem768` (Level 3 security, comparable to AES-192)
    *   `ml_kem1024` (Level 5 security, comparable to AES-256)
*   **Digital Signature Algorithm (DSA):** ML-DSA (formerly Dilithium), the successor to classic ECDSA signatures.
    *   `ml_dsa65` (Level 3 security)
    *   `ml_dsa87` (Level 5 security)

### Example Usage (Primitives)

```typescript
import { generateKeypair, encapsulate, decapsulate } from './src/ts/pqc';

// Encapsulation
const { publicKey, secretKey } = generateKeypair('ml_kem768');
const { cipherText, sharedSecret } = encapsulate(publicKey);
const retrievedSecret = decapsulate(cipherText, secretKey);

// sharedSecret will equal retrievedSecret
```

> **Note:** These are low-level cryptographic primitives. High-level functionality for tasks like file encryption and secure data channels will be built on top of these primitives in a future update.

## High-Level Hybrid Post-Quantum Encryption

This CLI now includes high-level hybrid encryption, combining post-quantum KEMs (ML-KEM) with traditional symmetric encryption (AES-256-GCM) via HKDF for robust, quantum-resistant data protection.

### Features

*   **Hybrid KEM:** Uses `ML-KEM-768` (Kyber) combined with `X25519` for shared secret establishment.
*   **Authenticated Encryption:** Employs `AES-256-GCM` for data encryption, ensuring confidentiality and integrity.
*   **Key Derivation:** Utilizes `HKDF-SHA512` to derive symmetric keys from shared secrets.
*   **File Encryption/Decryption:** Convenient functions to encrypt and decrypt entire files.

### CLI Commands

*   `quantumblue hybrid-keygen`: Generates a new hybrid public/secret key pair.
*   `quantumblue encrypt-file <input> <output> --pub <hex>`: Encrypts a file for a recipient.
*   `quantumblue decrypt-file <input> <output> --priv <hex>`: Decrypts a file using your private key.

### Example Usage (High-Level API)

```typescript
import { generateHybridKeypair, encrypt, decrypt } from './src/ts/crypto-high';

// Generate keys for Alice
const { publicKey: alicePubKey, secretKey: alicePrivKey } = generateHybridKeypair();

// Bob encrypts a message for Alice
const message = "Hello, Alice! This is a quantum-safe message from Bob.";
const encryptedData = encrypt(message, alicePubKey);

// Alice decrypts the message
const decryptedBytes = decrypt(encryptedData, alicePrivKey);
const decryptedMessage = new TextDecoder().decode(decryptedBytes);

// decryptedMessage will be "Hello, Alice! This is a quantum-safe message from Bob."
```

> **Warning:** Never commit your private keys or sensitive information directly into your repository. Use secure key management practices.
