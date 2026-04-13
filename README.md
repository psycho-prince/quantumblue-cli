
```text
   ____                       __                     ____   __            
  / __ \ __  __ ____ _ ____  / /_ __  __ ____ ___   / __ ) / /__  __ ___ 
 / / / // / / // __ `// __ \/ __// / / // __ `__ \ / __  |/ // / / // _ \
/ /_/ // /_/ // /_/ // / / // /_ / /_/ // / / / / // /_/ // // /_/ //  __/
\___\_\\__,_/ \__,_//_/ /_/ \__/ \__,_//_/ /_/ /_//_____//_/ \__,_/ \___/ 
                                                                          
```
# 🧿 QuantumBlue v2.0.0: The Gold Standard
### Sovereign PQC Notary. Built for the Post-Quantum Era.

[![Security: PQC](https://img.shields.io/badge/Security-ML--KEM--768%20|%20ML--DSA--65-blue.svg)](https://nist.gov/pqc)
[![License: ISC](https://img.shields.io/badge/License-ISC-green.svg)](https://opensource.org/licenses/ISC)
[![Build: Single Binary](https://img.shields.io/badge/Build-Go%20Binary-orange.svg)]()

QuantumBlue v2.0.0 is a complete re-architecture of the definitive command-line defense suite. Built in Go for high performance, it provides a cryptographic notary service for AI models, Web3 smart contracts, and mobile infrastructure.

---

## ⚡ v2.0.0 Core Features

### 🛡️ Quantum-Signed Envelopes (v2)
- **ML-KEM-768 (Kyber)**: Hybrid key exchange ensures confidentiality.
- **ML-DSA-65 (Dilithium)**: Authenticated digital signatures for immutable authorship.
- **Versioned Headers**: Portability and agility for long-term (10+ year) storage.

### 🧿 The Sovereign Daemon
- **Autonomous Notary**: Monitors your source directories (`.ts`, `.py`, `.sol`) and auto-seals them upon save.
- **Hardware-Backed Logic**: Uses a secure-store simulation (ready for JNI/CGO integration) for master key protection.

### 📂 Streaming Encryption
- **Large-Scale Assets**: Capable of protecting GB-scale AI models and binary artifacts with chunked streaming.

---

## 🚀 Quick Start

### Installation
Build the standalone binary:

```bash
go build -o quantumblue ./cmd/pqc-cli
sudo mv quantumblue /usr/local/bin/
```

### Usage

**1. Generate Your Identity**
```bash
quantumblue -mode=identity
```

**2. Seal and Sign a File**
```bash
quantumblue -mode=seal -file research_draft.pdf
```

**3. Start the Auto-Notary Daemon**
```bash
quantumblue -mode=daemon -watch ./src
```

**4. Unseal and Verify**
```bash
quantumblue -mode=unseal -file research_draft.pdf.pqc -sk-kem=pqc.sk -pk-dsa=id.pk
```

---

## 🛠️ Project Structure
- `internal/crypto`: ML-KEM, ML-DSA, and HMAC-SHA3-256 hybrid logic.
- `internal/daemon`: fsnotify-based directory monitoring for autonomous protection.
- `internal/storage`: Mock Secure Store for hardware-backed key protection.

---

## 📄 LICENSE: ISC
🧿 Protecting the future of digital heritage. info@quantum-blue.in
