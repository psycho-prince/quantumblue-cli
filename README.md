# QuantumBlue CLI

QuantumBlue is an enterprise-grade cryptographic discovery, migration, and compliance suite, designed to help organizations transition to Post-Quantum Cryptography (PQC).

## Architecture
The CLI is built in Go, providing high performance, cross-platform binary distribution, and reliable static analysis.

### Core Components
- `cmd/qb`: Entry point for the CLI.
- `internal/scanner`: Static analysis engine for cryptographic primitive detection and CBOM generation.
- `internal/policy`: Security policy enforcement engine for flagging forbidden algorithms (e.g., MD5).
- `internal/server`: REST API Daemon mode for remote scan orchestration.

## Getting Started

### Installation
1. Ensure Go is installed (v1.22+).
2. Clone the repository: `git clone <url>`
3. Build the binary: `go build -o qb ./cmd/qb/main.go`

### Usage
- **Scan a file:** `./qb scan <path/to/file.go>` (Outputs CBOM JSON)
- **Run in Daemon mode:** `./qb daemon <port>`

## Development
- **Tests:** `go test ./internal/...`
- **Distribution:** Configured with `goreleaser` for automated releases.
- **CI/CD:** Automated workflows in `.github/workflows/`.
