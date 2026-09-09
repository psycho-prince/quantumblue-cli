package policy

import (
	"testing"
)

func TestPolicy(t *testing.T) {
	p := DefaultQuantumRiskPolicy()
	sev, status := p.GetRisk("md5")
	if sev != SeverityCritical || status != StatusPolicyViolation {
		t.Errorf("Expected md5 to be CRITICAL and policy-violation, got %s, %s", sev, status)
	}
	sev, status = p.GetRisk("fips-203")
	if sev != SeverityLow || status != StatusCompliant {
		t.Errorf("Expected fips-203 to be LOW and compliant, got %s, %s", sev, status)
	}
}
