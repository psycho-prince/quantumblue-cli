# PQC Migration Guide

This guide outlines how to use the new AI-assisted Post-Quantum Cryptography (PQC) migration features in `quantumblue-cli`.

## Overview
The migration suite helps Blue Teams identify legacy cryptographic vulnerabilities and generate secure replacements based on NIST PQC standards (ML-KEM/ML-DSA).

## Usage

### 1. Analyzing Cryptographic Usage
Scan a directory for potential vulnerabilities in classical cryptographic function calls:
```bash
quantumblue -mode=analyze -target=./src/crypto
```

### 2. Performing PQC Migration
Trigger the full pipeline (Analysis -> Context Retrieval -> AI Generation) to generate PQC-compliant code:
```bash
quantumblue -mode=migrate -target=./src/crypto
```

## Prerequisites
- Set your `OPENAI_API_KEY` environment variable.
- Ensure the project has read access to the target directory.
