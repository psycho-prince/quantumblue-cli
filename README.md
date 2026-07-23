# QuantumBlue CLI

[![CI/CD Pipeline](https://github.com/psycho-prince/pqc-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/psycho-prince/pqc-sdk/actions/workflows/ci.yml)

QuantumBlue CLI is a production-ready, security-hardened toolkit for Post-Quantum Cryptography (PQC) and legal-tech evidence preservation. It empowers organizations to migrate existing cryptographic infrastructure to NIST-standardized quantum-resistant algorithms while ensuring legal admissibility of electronic records under Indian law (IT Act, Indian Evidence Act).

## Core Pillars
*   **Cryptographic Agility:** Hybrid signature scheme (ML-DSA + ECDSA) ensuring both quantum-resistance and immediate classical compatibility.
*   **Evidence Integrity:** RFC 3161 timestamping integration and tamper-evident audit logging for Section 65B(4) compliance.
*   **Standardized Discovery:** Automated generation of Cryptographic Bill of Materials (CBOM) for Go binaries, compiled binaries (ELF), and infrastructure configurations.
*   **Risk-Based Remediation:** Automated inventory risk scoring (CRITICAL to LOW) to prioritize cryptographic migration efforts.

## Quick Start

### Build
```bash
make
```

### Discovery & Prioritization
Scan infrastructure and generate a prioritized CBOM report:
```bash
./bin/qb -mode=analyze -target=/path/to/infrastructure
cat inventory.json
```

### Cryptographic Operations
Generate identity and seal files with PQC:
```bash
./bin/qb -mode=identity
./bin/qb -mode=seal -file=my-secret-doc.pdf
```

## Documentation
- [Legal Compliance Checklist](/docs/LEGAL_COMPLIANCE_CHECKLIST.md)
- [Technical Spec: Hybrid PQC & TSA](/docs/TECH_SPEC_HYBRID_PQC_TSA.md)
- [Security Policy](/SECURITY.md)
- [Contributing Guidelines](/CONTRIBUTING.md)

## License
Apache License 2.0
