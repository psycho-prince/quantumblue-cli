package rag

import (
	"context"

	"github.com/psycho-prince/pqc-sdk/internal/model"
	"github.com/psycho-prince/pqc-sdk/internal/policy"
)

type ContextPack struct {
	OrgID       string
	Question    string
	Findings    []model.CryptoUse
	Assets      []model.Asset
	Scores      []policy.ScoreExplanation
	Certs       []model.CertificateRecord
	TokenBudget int
}

// Store interface needed to fetch context
type Store interface {
	GetAssetsForOrg(ctx context.Context, orgID string) ([]model.Asset, error)
	GetFindingsForOrg(ctx context.Context, orgID string) ([]model.CryptoUse, error)
	GetCertsForOrg(ctx context.Context, orgID string) ([]model.CertificateRecord, error)
}

func Assemble(ctx context.Context, store Store, orgID, question string, budget int) (*ContextPack, error) {
	// 1. Fetch relevant assets, findings, certs from database, firmly isolated to orgID
	assets, err := store.GetAssetsForOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}
	
	findings, err := store.GetFindingsForOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}
	
	certs, err := store.GetCertsForOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}

	// Calculate risk scores (stubbed here, typically you'd call policy.Engine)
	var scores []policy.ScoreExplanation

	return &ContextPack{
		OrgID:       orgID,
		Question:    question,
		Findings:    findings,
		Assets:      assets,
		Certs:       certs,
		Scores:      scores,
		TokenBudget: budget,
	}, nil
}
