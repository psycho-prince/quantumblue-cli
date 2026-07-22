package analyzer

import (
	"bufio"
	"os"
	"regexp"
)

// FindSolidityCryptoCalls scans Solidity code for potential cryptographic function calls.
func FindSolidityCryptoCalls(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	re := regexp.MustCompile(`(ecrecover|keccak256|sha256)`)
	var calls []string
	
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if matches := re.FindAllString(scanner.Text(), -1); matches != nil {
			calls = append(calls, matches...)
		}
	}
	return calls, scanner.Err()
}
