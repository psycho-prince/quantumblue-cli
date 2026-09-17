package entitlement

import (
	"context"

	"github.com/psycho-prince/pqc-sdk/internal/model"
)

type FeatureChecker interface {
	IsEnabled(ctx context.Context, orgID, feature string) (bool, error)
}

type EntitlementStore interface {
	GetForOrg(ctx context.Context, orgID string) (*model.Entitlement, error)
}
