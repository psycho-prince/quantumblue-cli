package aws

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsarn "github.com/aws/aws-sdk-go-v2/aws/arn"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmTypes "github.com/aws/aws-sdk-go-v2/service/acm/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbTypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmsTypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3Types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/psycho-prince/pqc-sdk/internal/entitlement"
	"github.com/psycho-prince/pqc-sdk/internal/model"
)

// DefaultSessionDuration is the credential lifetime requested when assuming a role.
const DefaultSessionDuration = 3600 // 1 hour

// Config holds the AWS connector configuration. The role ARN and external ID
// come from the OrgAWSAccount DB record, never from the caller.
type Config struct {
	Organization      string
	RoleARN           string
	ExternalID        string
	Regions           []string
	EntitlementBypass bool
}

// AWSConnector discovers AWS resources via STS AssumeRole across registered regions.
type AWSConnector struct {
	config  Config
	checker entitlement.FeatureChecker
}

// NewAWSConnector creates a connector. If no regions are set, defaults to ap-south-1.
func NewAWSConnector(config Config, checker entitlement.FeatureChecker) *AWSConnector {
	if len(config.Regions) == 0 {
		config.Regions = []string{"ap-south-1"}
	}
	return &AWSConnector{config: config, checker: checker}
}

func (c *AWSConnector) Name() string {
	return "aws"
}

func generateID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
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

	// ─── STS AssumeRole ─────────────────────────────────────────────────────
	stCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("", "", "")),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load sts config: %w", err)
	}
	stsClient := sts.NewFromConfig(stCfg)

	assumed, err := stsClient.AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn:         aws.String(c.config.RoleARN),
		RoleSessionName: aws.String(fmt.Sprintf("quantumblue-%s", c.config.Organization)),
		ExternalId:      aws.String(c.config.ExternalID),
		DurationSeconds: aws.Int32(DefaultSessionDuration),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("sts assume-role failed: %w", err)
	}

	// Build per-region service clients from assumed credentials.
	assumedCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			*assumed.Credentials.AccessKeyId,
			*assumed.Credentials.SecretAccessKey,
			aws.ToString(assumed.Credentials.SessionToken),
		)),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build assumed-role config: %w", err)
	}

	var allAssets []model.Asset
	var allEdges []model.AssetEdge

	// Root account asset.
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
	meta, _ := json.Marshal(map[string]string{
		"role_arn":    c.config.RoleARN,
		"external_id": c.config.ExternalID,
		"account_id":  accountIDFromARN(c.config.RoleARN),
	})
	accountAsset.Metadata = meta
	allAssets = append(allAssets, accountAsset)

	// ─── Per-region discovery ───────────────────────────────────────────────
	for _, region := range c.config.Regions {
		regionCfg := assumedCfg
		regionCfg.Region = region // Region is awspires.Region (string alias)

		acmClient := acm.NewFromConfig(regionCfg)
		elbClient := elasticloadbalancingv2.NewFromConfig(regionCfg)
		s3Client := s3.NewFromConfig(regionCfg)
		kmsClient := kms.NewFromConfig(regionCfg)

		// ACM certificates
		certs, cerr := discoverACM(ctx, acmClient, c.config.Organization, region)
		if cerr == nil {
			allAssets = append(allAssets, certs...)
		}

		// ELB listeners
		listeners, lerr := discoverELB(ctx, elbClient, c.config.Organization, region)
		if lerr == nil {
			allAssets = append(allAssets, listeners...)
		}

		// S3 buckets
		buckets, berr := discoverS3(ctx, s3Client, c.config.Organization, region)
		if berr == nil {
			allAssets = append(allAssets, buckets...)
		}

		// KMS keys
		keys, kerr := discoverKMS(ctx, kmsClient, c.config.Organization, region)
		if kerr == nil {
			allAssets = append(allAssets, keys...)
		}
	}

	return allAssets, allEdges, nil
}

// accountIDFromARN extracts the 12-digit account ID from a role ARN.
func accountIDFromARN(roleARN string) string {
	parsed, err := awsarn.Parse(roleARN)
	if err != nil || parsed.AccountID == "" {
		return ""
	}
	return parsed.AccountID
}

// ─── Discovery helpers ───────────────────────────────────────────────────────

func discoverACM(ctx context.Context, client *acm.Client, orgID, region string) ([]model.Asset, error) {
	out, err := client.ListCertificates(ctx, &acm.ListCertificatesInput{
		MaxItems: aws.Int32(100),
	})
	if err != nil {
		return nil, fmt.Errorf("acm list certificates: %w", err)
	}

	var assets []model.Asset
	for _, cert := range out.CertificateSummaryList {
		if cert.DomainName == nil {
			continue
		}
		id := generateID()
		assets = append(assets, model.Asset{
			Id:             id,
			OrganizationId: orgID,
			Kind:           "ssl_certificate",
			Identifier:     fmt.Sprintf("aws/acm/%s/%s", region, *cert.DomainName),
			DisplayName:    cert.DomainName,
			Source:         "aws",
			Criticality:    "high",
			FirstSeenAt:    time.Now(),
			LastSeenAt:     time.Now(),
			Active:         true,
			Metadata:       certMetadata(cert),
		})
	}
	return assets, nil
}

func discoverELB(ctx context.Context, client *elasticloadbalancingv2.Client, orgID, region string) ([]model.Asset, error) {
	out, err := client.DescribeListeners(ctx, &elasticloadbalancingv2.DescribeListenersInput{
		PageSize: aws.Int32(100),
	})
	if err != nil {
		return nil, fmt.Errorf("elb describe listeners: %w", err)
	}

	var assets []model.Asset
	for _, l := range out.Listeners {
		if l.LoadBalancerArn == nil {
			continue
		}
		id := generateID()
		assets = append(assets, model.Asset{
			Id:             id,
			OrganizationId: orgID,
			Kind:           "load_balancer",
			Identifier:     fmt.Sprintf("aws/elbv2/%s/%s", region, *l.LoadBalancerArn),
			Source:         "aws",
			Criticality:    "high",
			FirstSeenAt:    time.Now(),
			LastSeenAt:     time.Now(),
			Active:         true,
			Metadata:       elbMetadata(l),
		})
	}
	return assets, nil
}

func discoverS3(ctx context.Context, client *s3.Client, orgID, region string) ([]model.Asset, error) {
	out, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, fmt.Errorf("s3 list buckets: %w", err)
	}

	var assets []model.Asset
	for _, b := range out.Buckets {
		if b.Name == nil {
			continue
		}
		id := generateID()
		assets = append(assets, model.Asset{
			Id:             id,
			OrganizationId: orgID,
			Kind:           "bucket",
			Identifier:     fmt.Sprintf("aws/s3/%s/%s", region, *b.Name),
			DisplayName:    b.Name,
			Source:         "aws",
			Criticality:    "medium",
			FirstSeenAt:    time.Now(),
			LastSeenAt:     time.Now(),
			Active:         true,
			Metadata:       s3Metadata(b),
		})
	}
	return assets, nil
}

func discoverKMS(ctx context.Context, client *kms.Client, orgID, region string) ([]model.Asset, error) {
	out, err := client.ListKeys(ctx, &kms.ListKeysInput{
		Limit: aws.Int32(100),
	})
	if err != nil {
		return nil, fmt.Errorf("kms list keys: %w", err)
	}

	var assets []model.Asset
	for _, k := range out.Keys {
		if k.KeyId == nil {
			continue
		}
		id := generateID()
		assets = append(assets, model.Asset{
			Id:             id,
			OrganizationId: orgID,
			Kind:           "kms_key",
			Identifier:     fmt.Sprintf("aws/kms/%s/%s", region, *k.KeyId),
			Source:         "aws",
			Criticality:    "high",
			FirstSeenAt:    time.Now(),
			LastSeenAt:     time.Now(),
			Active:         true,
			Metadata:       kmsMetadata(k),
		})
	}
	return assets, nil
}

// ─── Metadata helpers ─────────────────────────────────────────────────────────

func certMetadata(c acmTypes.CertificateSummary) json.RawMessage {
	m := map[string]interface{}{
		"domain":  aws.ToString(c.DomainName),
		"type":    string(c.Type),
		"arn":     aws.ToString(c.CertificateArn),
		"created": c.CreatedAt.String(),
	}
	b, _ := json.Marshal(m)
	return b
}

func elbMetadata(l elbTypes.Listener) json.RawMessage {
	m := map[string]interface{}{
		"load_balancer_arn": aws.ToString(l.LoadBalancerArn),
		"port":             int64(aws.ToInt32(l.Port)),
	}
	if l.SslPolicy != nil {
		m["ssl_policy"] = aws.ToString(l.SslPolicy)
	}
	if l.Certificates != nil {
		var certARNs []string
		for _, cert := range l.Certificates {
			if cert.CertificateArn != nil {
				certARNs = append(certARNs, aws.ToString(cert.CertificateArn))
			}
		}
		if len(certARNs) > 0 {
			m["certificates"] = certARNs
		}
	}
	b, _ := json.Marshal(m)
	return b
}

func s3Metadata(b s3Types.Bucket) json.RawMessage {
	m := map[string]interface{}{
		"name":          aws.ToString(b.Name),
		"creation_date": b.CreationDate,
	}
	b2, _ := json.Marshal(m)
	return b2
}

func kmsMetadata(k kmsTypes.KeyListEntry) json.RawMessage {
	m := map[string]interface{}{
		"key_id": aws.ToString(k.KeyId),
		"arn":    aws.ToString(k.KeyArn),
	}
	b, _ := json.Marshal(m)
	return b
}
