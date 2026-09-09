package policy

import "strings"

// Severity levels
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
)

// Quantum status
const (
	StatusPolicyViolation   = "policy-violation"
	StatusQuantumVulnerable = "quantum-vulnerable"
	StatusCompliant         = "compliant"
)

// QuantumRiskPolicy defines cryptographic primitive risk levels for PQC.
type QuantumRiskPolicy struct {
	RiskLevels   map[string]string
	QuantumStatus map[string]string
}

func DefaultQuantumRiskPolicy() *QuantumRiskPolicy {
	return &QuantumRiskPolicy{
		RiskLevels: map[string]string{
			"md5":           SeverityCritical,
			"des":           SeverityCritical,
			"rc4":           SeverityCritical,
			"sha1":          SeverityCritical,
			"rsa-1024":      SeverityCritical,
			"rsa-2048":      SeverityHigh,
			"rsa-4096":      SeverityHigh,
			"ecdsa":         SeverityHigh,
			"ecdh":          SeverityHigh,
			"curve25519":    SeverityHigh,
			"ed25519":       SeverityHigh,
			"tls1.2-non-pqc": SeverityHigh,
			"fips-203":      SeverityLow,
			"fips-204":      SeverityLow,
			"ml-kem-768":    SeverityLow,
			"ml-dsa-65":     SeverityLow,
			"aes-256-gcm":   SeverityLow,
			"sha-384":       SeverityLow,
			"sha3-256":      SeverityLow,
		},
		QuantumStatus: map[string]string{
			"md5":           StatusPolicyViolation,
			"des":           StatusPolicyViolation,
			"rc4":           StatusPolicyViolation,
			"sha1":          StatusPolicyViolation,
			"rsa-1024":      StatusPolicyViolation,
			"rsa-2048":      StatusQuantumVulnerable,
			"rsa-4096":      StatusQuantumVulnerable,
			"ecdsa":         StatusQuantumVulnerable,
			"ecdh":          StatusQuantumVulnerable,
			"curve25519":    StatusQuantumVulnerable,
			"ed25519":       StatusQuantumVulnerable,
			"tls1.2-non-pqc": StatusQuantumVulnerable,
			"fips-203":      StatusCompliant,
			"fips-204":      StatusCompliant,
			"ml-kem-768":    StatusCompliant,
			"ml-dsa-65":     StatusCompliant,
			"aes-256-gcm":   StatusCompliant,
			"sha-384":       StatusCompliant,
			"sha3-256":      StatusCompliant,
		},
	}
}

// GetRisk returns the severity and quantum status for a primitive.
func (p *QuantumRiskPolicy) GetRisk(primitive string) (string, string) {
	lower := strings.ToLower(primitive)
	for pattern, severity := range p.RiskLevels {
		if strings.Contains(lower, pattern) {
			return severity, p.QuantumStatus[pattern]
		}
	}
	return SeverityMedium, StatusPolicyViolation
}
