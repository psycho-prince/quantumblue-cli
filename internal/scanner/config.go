package scanner

import (
	"bufio"
	"fmt"
	"os"
	"regexp"

	"github.com/psycho-prince/pqc-sdk/internal/policy"
)

// ConfigScanner implements DiscoveryScanner for configuration and infrastructure files.
type ConfigScanner struct {
	patterns []*regexp.Regexp
}

// NewConfigScanner initializes a new ConfigScanner with common cryptographic regex patterns.
func NewConfigScanner() *ConfigScanner {
	return &ConfigScanner{
		patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)TLSv1\.0|TLSv1\.1`),
			regexp.MustCompile(`(?i)MD5|SHA1`),
			regexp.MustCompile(`(?i)RSA-[0-9]{3,4}`),
		},
	}
}

// Scan inspects a file for cryptographic configuration patterns.
func (s *ConfigScanner) Scan(path string) ([]CBOMItem, error) {
	findings := []CBOMItem{}
	p := policy.DefaultPolicy()

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNumber := 1
	for scanner.Scan() {
		line := scanner.Text()
		for _, pattern := range s.patterns {
			if pattern.MatchString(line) {
				primitive := pattern.String()
				findings = append(findings, CBOMItem{
					Primitive: primitive,
					Location:  fmt.Sprintf("%s:%d", path, lineNumber),
					Severity:  p.GetSeverity(primitive),
					Type:      "config",
				})
			}
		}
		lineNumber++
	}

	return findings, scanner.Err()
}
