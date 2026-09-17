package reporter

import (
	"context"
	"encoding/json"

	"github.com/psycho-prince/pqc-sdk/internal/graph"
	"github.com/psycho-prince/pqc-sdk/internal/model"
)

type JSONReporter struct {
	graph *graph.GraphStore
}

func NewJSONReporter(g *graph.GraphStore) *JSONReporter {
	return &JSONReporter{graph: g}
}

func (r *JSONReporter) Generate(ctx context.Context, orgID string, assets []model.Asset) ([]byte, error) {
	return json.MarshalIndent(assets, "", "  ")
}
