package orchestrator

import (
	"context"
	"fmt"
	"github.com/psycho-prince/pqc-sdk/internal/transform"
)

// Pipeline orchestrates the PQC migration process.
type Pipeline struct {
	Transformer transform.Transformer
}

// RunMigration scans the target directory and generates PQC replacements.
func (p *Pipeline) RunMigration(ctx context.Context, targetDir string) error {
	fmt.Printf("🚀 Starting migration for: %s\n", targetDir)
	
	// 1. Analyze
	
	// 2. Retrieve context
	guidelines := "Use ML-KEM-768 for KEM and ML-DSA-65 for DSA."
	
	// 3. Generate replacement
	codeContext := "Existing RSA-2048 encryption logic."
	replacement, err := p.Transformer.GeneratePQCReplacement(ctx, codeContext, guidelines)
	if err != nil {
		return err
	}
	
	fmt.Printf("✨ Generated PQC Code:\n%s\n", replacement)
	return nil
}
