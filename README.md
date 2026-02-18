# QuantumBlue CLI

**AI-Powered Quantum Cybersecurity Blue Team Tool**

QuantumBlue is a command-line interface designed to help developers and security professionals (blue teams) prepare for the post-quantum era. It combines state-of-the-art hybrid post-quantum cryptography with an AI-powered agent to provide analysis, threat prediction, and system hardening recommendations.

---

## Features

*   **Hybrid Post-Quantum Cryptography**: Implements ML-KEM-768 (Kyber) combined with X25519 for robust, forward-secret encryption of strings and files.
*   **Agentic AI**: Features an integrated Python-based AI agent (QuantumBlue Agent) that can be queried using natural language to get expert analysis on quantum threats and PQC migration strategies.
*   **Autonomy Levels**: Inspired by agentic runtimes, the CLI operates at different autonomy levels (`readonly`, `supervised`, `full`) to ensure safety and user control over sensitive operations.
*   **Natural Language Interface**: The CLI can parse simple natural language commands, and forwards complex queries directly to the QuantumBlue Agent.
*   **Secure by Design**: Enforces a strict security policy with an action allowlist and a sandboxed path resolution system (`resolveSafePath`) to prevent unauthorized file system access.

## Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-repo/quantumblue-cli.git
    cd quantumblue-cli
    ```

2.  **Install dependencies:**
    ```bash
    npm install
    # Install Python dependencies for the agent
    pip install litellm
    ```

3.  **Link the CLI for global use:**
    ```bash
    npm link
    ```

## Usage Examples

### 1. Generate a Keypair

Create a new hybrid PQC keypair.

```bash
quantumblue generate-keypair
```

### 2. Encrypt/Decrypt a String

Encrypt a short message using a recipient's public key.

```bash
# (This is a long command, you would typically use variables)
quantumblue encrypt --text "secret message" --pub 02...
quantumblue decrypt --iv <iv> --cipher <cipher> --tag <tag> --kem <kem> --priv <priv>
```

### 3. Encrypt/Decrypt a File

Securely encrypt a file.

```bash
# Create a secret file
echo "My top secret data." > secret.txt

# Encrypt it
quantumblue encrypt-file --input secret.txt --output secret.enc --pub <your-public-key>

# Decrypt it
quantumblue decrypt-file --input secret.enc --output secret.dec --priv <your-private-key>
```

### 4. Query the AI Agent

Use natural language to ask the QuantumBlue Agent for analysis.

```bash
quantumblue 'predict the impact of quantum computing on Bitcoin by 2030'
```
```json
{
  "thought": "The user is asking for a quantum threat assessment on Bitcoin. I need to analyze its cryptographic underpinnings (ECDSA) and provide an actionable prediction.",
  "action": "predict",
  "data": {
    "target": "Bitcoin (BTC)",
    "threat": "Shor's Algorithm breaking the ECDSA signatures used for transactions.",
    "risk_level": "Critical",
    "timeframe": "2028-2032",
    "recommendation": "Monitor proposals for PQC algorithms in the Bitcoin protocol (BIPs). Assets should be held in PQC-safe wallets once available. Do not reuse addresses.",
    "hardening_steps": []
  }
}
```
