package aws

import (
	"context"
	"fmt"
	"time"
	"encoding/json"
	"crypto/rand"
	"encoding/hex"

	"github.com/psycho-prince/pqc-sdk/internal/entitlement"
	"github.com/psycho-prince/pqc-sdk/internal/model"
)

type Config struct {
	Organization      string
	RoleARN           string
	ExternalID        string
	Regions           []string
	EntitlementBypass bool
}

type AWSConnector struct {
	config  Config
	checker entitlement.FeatureChecker
}

func NewAWSConnector(config Config, checker entitlement.FeatureChecker) *AWSConnector {
	if len(config.Regions) == 0 {
		config.Regions = []string{"ap-south-1"} // Default to India regions per work order
	}
	return &AWSConnector{config: config, checker: checker}
}

func (c *AWSConnector) Name() string {
	return "aws"
}

func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (c *AWSConnector) Discover(ctx context.Context) ([]model.Asset, []model.AssetEdge, error) {
	if !c.config.EntitlementBypass && c.checker != nil {
		enabled, err := c.checker.IsEnabled(ctx, c.config.Organization, "aws_connector")
		if err != nil {
			return nil, nil, fmt.Errorf("entitlement check failed: %w", err)
		}
		if !enabled {
			return nil, nil, fmt.Errorf("organization %s is not entitled to feature aws_connector", c.config.Organization)
		}
	}

	var assets []model.Asset
	var edges []model.AssetEdge

	// We create a root asset representing the AWS account
	accountAsset := model.Asset{
		Id:             generateID(),
		OrganizationId: c.config.Organization,
		Kind:           "cloud_account",
		Identifier:     fmt.Sprintf("aws/%s", c.config.RoleARN),
		Source:         "aws",
		Criticality:    "unknown",
		FirstSeenAt:    time.Now(),
		LastSeenAt:     time.Now(),
		Active:         true,
	}
	meta, _ := json.Marshal(map[string]string{"role_arn": c.config.RoleARN, "external_id": c.config.ExternalID})
	accountAsset.Metadata = meta
	assets = append(assets, accountAsset)

	// Here we would use the AWS SDK to assume the role and list resources.
	// For example:
	// - ACM certificates (Asset{kind:"certificate"})
	// - ALB/ELB load balancers (Asset{kind:"endpoint"})
	// - S3 buckets
	// - KMS keys
	
	// This is the scaffold implementation. It returns just the account asset.

	return assets, edges, nil
}
