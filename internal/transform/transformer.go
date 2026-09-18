package transform

import (
	"context"
	"fmt"
)

// Transformer defines the interface for PQC code generation.
type Transformer interface {
	GeneratePQCReplacement(ctx context.Context, codeContext string, guidelines string) (string, error)
}

// RuleBasedTransformer implements the Transformer interface using template matching.
type RuleBasedTransformer struct{}

// NewRuleBasedTransformer initializes a new rule-based transformer.
func NewRuleBasedTransformer() *RuleBasedTransformer {
	return &RuleBasedTransformer{}
}

// GeneratePQCReplacement maps classical crypto patterns to PQC equivalents using rules.
func (t *RuleBasedTransformer) GeneratePQCReplacement(ctx context.Context, codeContext string, guidelines string) (string, error) {
	if contains(codeContext, "RSA") {
		return "// PQC Replacement (Rule-Based)\n// Replaced RSA with ML-KEM-768 for KEM\n// Replaced RSA with ML-DSA-65 for DSA", nil
	}

	return "", fmt.Errorf("no rule found for context: %s", codeContext)
}

func contains(s, substr string) bool {
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
