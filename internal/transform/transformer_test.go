package transform

import (
	"context"
	"testing"
)

func TestRuleBasedTransformer(t *testing.T) {
	transformer := NewRuleBasedTransformer()
	ctx := context.Background()

	result, err := transformer.GeneratePQCReplacement(ctx, "RSA-2048", "guidelines")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == "" {
		t.Fatal("Expected non-empty result")
	}
}
