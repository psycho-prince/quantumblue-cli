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
