package entitlement

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/psycho-prince/pqc-sdk/internal/model"
)

type DBEntitlementStore struct {
	db *sql.DB
}

func NewDBEntitlementStore(db *sql.DB) *DBEntitlementStore {
	return &DBEntitlementStore{db: db}
}

func (s *DBEntitlementStore) GetForOrg(ctx context.Context, orgID string) (*model.Entitlement, error) {
	query := `SELECT id, organizationId, planCode, source, maxDomains, maxAssets, scansPerMonth, features
	          FROM Entitlement WHERE organizationId = ? LIMIT 1`

	var e model.Entitlement
	// Scan features as a string since SQLite uses TEXT for JSON
	var featuresStr sql.NullString
	err := s.db.QueryRowContext(ctx, query, orgID).Scan(
		&e.Id,
		&e.OrganizationId,
		&e.PlanCode,
		&e.Source,
		&e.MaxDomains,
		&e.MaxAssets,
		&e.ScansPerMonth,
		&featuresStr,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to fetch entitlement: %w", err)
	}
	if featuresStr.Valid {
		e.Features = model.FeaturesFromString(featuresStr.String)
	}
	return &e, nil
}

type DBFeatureChecker struct {
	store EntitlementStore
}

func NewDBFeatureChecker(store EntitlementStore) *DBFeatureChecker {
	return &DBFeatureChecker{store: store}
}

func (c *DBFeatureChecker) IsEnabled(ctx context.Context, orgID, feature string) (bool, error) {
	e, err := c.store.GetForOrg(ctx, orgID)
	if err != nil {
		return false, err
	}
	if e == nil {
		return false, nil
	}
	return e.HasFeature(feature), nil
}
