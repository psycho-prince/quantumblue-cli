package entitlement

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

type OrgAWSAccount struct {
	Id             string
	OrganizationId string
	AccountId      string
	RoleArn        string
	ExternalId     string
	Enabled        bool
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

type AWSAccountStore interface {
	GetForOrgAndAccount(ctx context.Context, orgID, accountID string) (*OrgAWSAccount, error)
}

type DBAWSAccountStore struct {
	db *sql.DB
}

func NewDBAWSAccountStore(db *sql.DB) *DBAWSAccountStore {
	return &DBAWSAccountStore{db: db}
}

func (s *DBAWSAccountStore) GetForOrgAndAccount(ctx context.Context, orgID, accountID string) (*OrgAWSAccount, error) {
	query := `SELECT id, "organizationId", "accountId", "roleArn", "externalId", enabled, "createdAt", "updatedAt"
          FROM "OrgAWSAccount" WHERE "organizationId" = $1 AND "accountId" = $2 AND enabled = true LIMIT 1`

	var a OrgAWSAccount
	err := s.db.QueryRowContext(ctx, query, orgID, accountID).Scan(
		&a.Id,
		&a.OrganizationId,
		&a.AccountId,
		&a.RoleArn,
		&a.ExternalId,
		&a.Enabled,
		&a.CreatedAt,
		&a.UpdatedAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to fetch AWS account: %w", err)
	}

	return &a, nil
}

// Insert adds a new OrgAWSAccount record. Returns the created record or an error.
func (s *DBAWSAccountStore) Insert(ctx context.Context, orgID, accountID, roleARN, externalID string) (*OrgAWSAccount, error) {
	query := `INSERT INTO "OrgAWSAccount" ("organizationId", "accountId", "roleArn", "externalId")
          VALUES ($1, $2, $3, $4)
          RETURNING id, "organizationId", "accountId", "roleArn", "externalId", enabled, "createdAt", "updatedAt"`

	var a OrgAWSAccount
	err := s.db.QueryRowContext(ctx, query, orgID, accountID, roleARN, externalID).Scan(
		&a.Id,
		&a.OrganizationId,
		&a.AccountId,
		&a.RoleArn,
		&a.ExternalId,
		&a.Enabled,
		&a.CreatedAt,
		&a.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to insert AWS account: %w", err)
	}

	return &a, nil
}
