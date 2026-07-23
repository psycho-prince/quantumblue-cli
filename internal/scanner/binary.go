package scanner

import (
	"debug/elf"
	"os"
)

// BinaryScanner implements DiscoveryScanner for compiled binaries.
type BinaryScanner struct{}

// NewBinaryScanner initializes a new BinaryScanner.
func NewBinaryScanner() *BinaryScanner {
	return &BinaryScanner{}
}

// Scan inspects a binary for cryptographic symbols.
func (s *BinaryScanner) Scan(path string) ([]CBOMItem, error) {
	findings := []CBOMItem{}

	// Open the file
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Currently supporting ELF (Linux binaries)
	ef, err := elf.NewFile(f)
	if err != nil {
		// Not an ELF file, skip
		return findings, nil
	}
	defer ef.Close()

	// Analyze symbols
	syms, err := ef.Symbols()
	if err != nil {
		return findings, nil // No symbols found
	}

	for _, sym := range syms {
		// Look for crypto-related symbol names
		if isCryptoSymbol(sym.Name) {
			findings = append(findings, CBOMItem{
				Primitive: sym.Name,
				Location:  path,
				Severity:  "medium",
				Type:      "binary",
			})
		}
	}
	return findings, nil
}

func isCryptoSymbol(name string) bool {
	// Simple heuristic check for common crypto symbols
	cryptoKeywords := []string{"AES", "RSA", "SHA", "ECDSA", "Kyber", "Dilithium"}
	for _, k := range cryptoKeywords {
		if contains(name, k) {
			return true
		}
	}
	return false
}
