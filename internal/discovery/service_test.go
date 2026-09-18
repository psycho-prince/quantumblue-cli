package discovery

import (
	"context"
	"testing"
	"time"

	"github.com/psycho-prince/pqc-sdk/internal/model"
	"github.com/psycho-prince/pqc-sdk/internal/policy"
)

func TestNewService(t *testing.T) {
	svc, err := NewService()
	if err != nil {
		t.Fatalf("NewService failed: %v", err)
	}
	if svc == nil {
		t.Fatal("NewService returned nil")
	}
	if svc.policyEngine == nil {
		t.Fatal("policyEngine not initialized")
	}
	if len(svc.policyEngine.Rules) == 0 {
		t.Fatal("policy engine has no rules")
	}
}

func TestService_Discover_EmptyDomain(t *testing.T) {
	svc, err := NewService()
	if err != nil {
		t.Fatal(err)
	}

	// Empty domain may or may not error depending on DNS package behavior;
	// the important thing is it doesn't panic.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = svc.Discover(ctx, "org-test", "")
	// Just verify we get some result or error, not a panic
	_ = err
}

func TestService_RiskSummary(t *testing.T) {
	svc, err := NewService()
	if err != nil {
		t.Fatal(err)
	}

	result := &DiscoveryResult{
		Domain:      "example.com",
		CryptoUses: []model.CryptoUse{
			{Primitive: "RSA", Role: "key_exchange", KeyBits: intPtr(2048)},
			{Primitive: "ML-KEM-768", Role: "key_exchange"},
			{Primitive: "SHA256", Role: "hash"},
		},
	}

	summary := svc.RiskSummary(result)

	if summary["domain"] != "example.com" {
		t.Errorf("domain mismatch: %v", summary["domain"])
	}
	if summary["total_crypto"].(int) != 3 {
		t.Errorf("total_crypto mismatch: %v", summary["total_crypto"])
	}
	// SHA256 is not in policy rules → "medium" (unknown primitive fallback), counted as finding
	// ML-KEM-768 is informational → not counted as finding
	// RSA-2048 key_exchange → high → counted as finding
	if summary["findings_count"].(int) != 2 {
		t.Errorf("findings_count mismatch: %v (expected 2: RSA-2048 key_exchange=high + SHA256=medium)", summary["findings_count"])
	}
}

func intPtr(v int) *int {
	return &v
}

// Test policy engine scoring against the actual YAML rules.
func TestPolicyEngine_Scoring(t *testing.T) {
	engine, err := policy.NewEngine()
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		primitive string
		role      string
		keyBits   *int
		wantRisk  string
		wantQS    string
	}{
		{"RSA key_exchange 2048", "RSA", "key_exchange", intPtr(2048), "high", "vulnerable"},
		{"RSA key_exchange 4096", "RSA", "key_exchange", intPtr(4096), "medium", "vulnerable"},
		{"RSA signature", "RSA", "signature", nil, "low", "vulnerable"},
		{"ML-DSA-65 signature", "ML-DSA-65", "signature", nil, "informational", "resistant"},
		{"ML-KEM-768 key_exchange", "ML-KEM-768", "key_exchange", nil, "informational", "resistant"},
		{"Unknown primitive", "UNKNOWN-ALGO", "encryption", nil, "medium", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score := engine.ScoreFinding(model.CryptoUse{
				Primitive: tt.primitive,
				Role:      tt.role,
				KeyBits:   tt.keyBits,
			})
			if score.Risk != tt.wantRisk {
				t.Errorf("risk = %q, want %q", score.Risk, tt.wantRisk)
			}
			if score.QuantumStatus != tt.wantQS {
				t.Errorf("quantumStatus = %q, want %q", score.QuantumStatus, tt.wantQS)
			}
		})
	}
}

// Test that Discover doesn't panic on empty domain and returns quickly.
func TestDiscover_NoPanic(t *testing.T) {
	svc, err := NewService()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := svc.Discover(ctx, "org-test", "")
		done <- err
	}()

	select {
	case <-done:
		// OK — completed without panic
	case <-time.After(15 * time.Second):
		t.Fatal("Discover timed out (possible deadlock)")
	}
}
