package analyzer_test

import (
	"os"
	"testing"
	"github.com/psycho-prince/pqc-sdk/internal/analyzer"
)

func TestFindPythonCryptoCalls(t *testing.T) {
	// Create a temporary file with Python crypto code
	tmpFile := "test_code.py"
	content := "import cryptography.hazmat.primitives.ciphers\nfrom hashlib import sha256\n"
	os.WriteFile(tmpFile, []byte(content), 0644)
	defer os.Remove(tmpFile)

	calls, err := analyzer.FindPythonCryptoCalls(tmpFile)
	if err != nil {
		t.Fatalf("Failed to scan: %v", err)
	}

	if len(calls) == 0 {
		t.Errorf("Expected to find crypto calls, found none")
	}
}
