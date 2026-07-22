# QuantumBlue CLI

🧿 **QuantumBlue v2.0.0: The Sovereign PQC Notary**

QuantumBlue is a command-line defense suite designed for the post-quantum era. It provides cryptographic notary services, autonomous directory monitoring, and automated PQC migration analysis to protect AI models, smart contracts, and infrastructure against quantum-enabled threats.

## ⚡ Core Capabilities

### 1. PQC Migration Suite (Diagnosis & Planning)
QuantumBlue assists Blue Teams in identifying legacy cryptographic vulnerabilities and planning migration to NIST-standardized PQC primitives (ML-KEM/ML-DSA).

*   **`-mode=analyze`**: Performs a cryptographic inventory scan on a target directory, identifying legacy primitives (e.g., `ecrecover`, `keccak256`) and exporting a structured `inventory.json` for risk assessment.
*   **`-mode=migrate`**: Executes a migration pipeline (Analysis -> Context Retrieval -> AI Generation) to generate secure PQC-compliant replacement code.

### 2. Sovereign Notary (Seal & Verify)
*   **`-mode=seal`**: Signs and seals files using ML-KEM-768 for confidentiality and ML-DSA-65 for immutable authorship.
*   **`-mode=unseal`**: Verifies signatures and decrypts Quantum-Signed Envelopes.

### 3. Sovereign Daemon
*   **`-mode=daemon`**: Monitors source directories (`.ts`, `.py`, `.sol`) and auto-seals them upon save to ensure continuous protection.

---

## 🚀 Quick Start

### Installation
```bash
go build -o quantumblue ./cmd/pqc-cli
# Add to PATH
```

### Usage Examples

**Analyze a project for legacy cryptography:**
```bash
quantumblue -mode=analyze -target=./src/contracts
```

**Seal a sensitive asset:**
```bash
quantumblue -mode=seal -file research_data.pdf
```

---

## 🛡️ Security Mandates
- Never commit `pqc.sk` or `id.sk` (private keys) to source control.
- Ensure `OPENAI_API_KEY` is managed securely as an environment variable for migration features.
