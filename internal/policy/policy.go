package policy

import "strings"

// Severity levels
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
)

// Policy defines cryptographic primitive risk levels.
type Policy struct {
	RiskLevels map[string]string
}

func DefaultPolicy() *Policy {
	return &Policy{
		RiskLevels: map[string]string{
			"md5":      SeverityCritical,
			"des":      SeverityCritical,
			"rc4":      SeverityCritical,
			"sha1":     SeverityHigh,
			"rsa-1024": SeverityHigh,
			"tls1.0":   SeverityHigh,
			"tls1.1":   SeverityHigh,
		},
	}
}

// GetSeverity returns the risk level for a primitive, defaulting to MEDIUM.
func (p *Policy) GetSeverity(primitive string) string {
	lower := strings.ToLower(primitive)
	for pattern, severity := range p.RiskLevels {
		if strings.Contains(lower, pattern) {
			return severity
		}
	}
	return SeverityMedium
}
