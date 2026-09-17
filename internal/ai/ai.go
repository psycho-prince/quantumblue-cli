package ai

import (
	"context"
	"errors"
	"fmt"

	"github.com/openai/openai-go"
	"github.com/psycho-prince/pqc-sdk/internal/rag"
)

type Citation struct {
	ID string `json:"id"`
}

type Answer struct {
	Text       string
	Citations  []Citation
	Confidence string // high | medium | low
	UsedRows   int
}

func Ask(ctx context.Context, client *openai.Client, pack *rag.ContextPack) (*Answer, error) {
	usedRows := len(pack.Findings) + len(pack.Assets) + len(pack.Certs)
	if usedRows == 0 {
		return nil, errors.New("insufficient data")
	}

	// In a real implementation we would convert the pack into a JSON string context,
	// inject it into the system prompt, and parse the output.
	
	// We'll stub this based on the work order instructions
	// Multi-tenant isolation was already enforced in rag.Assemble
	// AI has read-only context

	var citations []Citation
	for _, f := range pack.Findings {
		citations = append(citations, Citation{ID: f.Id})
	}

	// Fallback/stub for AI call
	ans := &Answer{
		Text:       fmt.Sprintf("Based on the %d assets and findings found in your inventory, here is the assessment...", usedRows),
		Citations:  citations,
		Confidence: "medium",
		UsedRows:   usedRows,
	}

	return ans, nil
}
