package connector

import (
	"context"

	"github.com/psycho-prince/pqc-sdk/internal/model"
)

// Connector defines the interface for external asset discovery and scanning sources.
type Connector interface {
	// Discover returns a list of assets and edges found by this connector.
	Discover(ctx context.Context) ([]model.Asset, []model.AssetEdge, error)
	// Name returns the identifier of the connector (e.g., "github", "aws").
	Name() string
}
