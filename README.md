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

## ⚠️ Project Status & Assessment

QuantumBlue is currently an **experimental, early-stage prototype**.

- **Purpose**: Designed as a supplementary scanning and prototyping aid for Blue Teams and researchers.
- **AI-Assisted Migration**: While the migration pipeline leverages AI for code generation, **it must never be trusted blindly for production**. All AI-generated cryptographic code requires expert review, side-channel analysis, and thorough testing.
- **Maturity**: This project lacks battle-testing and community validation. It is not intended as a production-grade enterprise solution.
- **Security**: Treat this tool as an experimental assistant. For critical production PQC migrations, prioritize established, battle-tested cryptographic libraries (e.g., `liboqs`, `OpenSSL 3.x` with PQC support) and manual security audits.

---

## 🗺️ Roadmap & Future Direction

We are evolving QuantumBlue into a robust, enterprise-ready PQC migration platform.

### Core Architecture & Reliability
- **Hybrid Migration**: Move beyond LLM-only generation to mandatory rule-based/template-based transformations (e.g., integrating `liboqs`, `OpenSSL`).
- **Static Analysis**: Integrate advanced static analysis (Semgrep, custom AST parsers) for more accurate crypto discovery.
- **Human-in-the-Loop**: Implement diff reviews, approval gates, and automated test enforcement for AI-generated suggestions.
- **Tech Stack Consolidation**: Standardize on a primary language (Go) and provide native, signed standalone binaries.

### Enterprise Features
- **Comprehensive Discovery**: Expand scanning to binaries, containers, cloud configurations, and database encryption settings.
- **CBOM**: Generate standardized Cryptographic Bill of Materials.
- **Hybrid Support**: Support seamless transition periods (classical + PQC).
- **Scalability**: Implement REST API, daemon authentication/audit trails, and integration with SIEM/Enterprise tools.

### Security & Crypto Hardening
- **Formal Validation**: Focus on side-channel resistance and constant-time implementations.
- **Key Management**: Add support for Hardware Security Modules (HSMs) and zero-trust key storage practices.

### Practical Improvements
- **Configuration**: Implement YAML/JSON-based config management and environment-aware profiles.
- **UX**: Enhance error handling, progress monitoring, and rollback capabilities.

---

## 🚀 Quick Start

### Installation (Recommended)
Install the CLI globally via NPM:

```bash
npm install -g quantumblue-cli
```
You can now run the tool directly using the `quantumblue` command.

### Installation (From Source)
Build the standalone binary manually:

```bash
go build -o quantumblue ./cmd/pqc-cli
# Add the binary to your PATH
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
