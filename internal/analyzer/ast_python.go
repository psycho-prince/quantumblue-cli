package analyzer

import (
	"bufio"
	"os"
	"regexp"
)

// FindPythonCryptoCalls scans Python code for potential cryptographic function calls using regex.
func FindPythonCryptoCalls(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Simple regex for common crypto library imports/calls
	re := regexp.MustCompile(`(cryptography|hashlib|PyCrypto|pycryptodome)\.([a-zA-Z0-9_]+)`)
	var calls []string
	
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		matches := re.FindAllStringSubmatch(scanner.Text(), -1)
		for _, match := range matches {
			if len(match) > 2 {
				calls = append(calls, match[2])
			}
		}
	}
	return calls, scanner.Err()
}
