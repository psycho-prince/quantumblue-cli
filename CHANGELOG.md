# Changelog - QuantumBlue CLI v2.1.0

## Features
- **Rule-Based Transformation Engine:** Decoupled OpenAI dependency, implemented native rule-based PQC code generation.
- **Extensible Discovery:** New modular scanner architecture supporting Go source, compiled binaries, and infrastructure configurations.
- **Cryptographic Standardization:** Transitioned PQC primitives to `cloudflare/circl`.
- **Security Governance:** Implemented structured `AuditLogger` for cryptographic operations.
- **Release Automation:** Integrated `GoReleaser` for automated multi-platform binary signing/distribution.

## Enhancements
- Standardized discovery output to CBOM format.
- Implemented heuristic risk-based prioritization of cryptographic assets.
- Refactored build process with `Makefile`.
- Improved `.gitignore` and build artifact management.

## Bug Fixes
- Fixed scanner out-of-bounds crash during directory traversal.
