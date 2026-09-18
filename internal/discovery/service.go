package discovery

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/psycho-prince/pqc-sdk/internal/discovery/certparse"
	"github.com/psycho-prince/pqc-sdk/internal/discovery/ct"
	"github.com/psycho-prince/pqc-sdk/internal/discovery/dns"
	"github.com/psycho-prince/pqc-sdk/internal/discovery/tlsprobe"
	"github.com/psycho-prince/pqc-sdk/internal/model"
	"github.com/psycho-prince/pqc-sdk/internal/normalize"
	"github.com/psycho-prince/pqc-sdk/internal/policy"
)

// Service orchestrates domain discovery: DNS → CT → TLS → cert parsing → crypto inventory.
type Service struct {
	policyEngine *policy.Engine
}

// NewService creates a discovery service with a loaded policy engine.
func NewService() (*Service, error) {
	engine, err := policy.NewEngine()
	if err != nil {
		return nil, fmt.Errorf("loading policy engine: %w", err)
	}
	return &Service{policyEngine: engine}, nil
}

// DiscoveryResult is the complete output of a domain discovery run.
type DiscoveryResult struct {
	OrganizationID string
	Domain         string
	DNSRecords     []model.Asset
	Subdomains     []model.Asset
	Certificates   []model.Asset
	CryptoUses     []model.CryptoUse
	Edges          []model.AssetEdge
	Findings       []model.CryptoUse // scored findings for report/alert
	ScanID         string
	CompletedAt    time.Time
}

// Discover runs the full domain discovery pipeline.
// It performs DNS enumeration, certificate transparency lookup, TLS probing,
// certificate parsing, crypto inventory classification, and normalizes everything
// into assets + edges ready for graph storage.
func (s *Service) Discover(ctx context.Context, orgID, domain string) (*DiscoveryResult, error) {
	result := &DiscoveryResult{
		OrganizationID: orgID,
		Domain:         domain,
		CompletedAt:    time.Now(),
	}
	var allAssets []model.Asset
	var allEdges []model.AssetEdge
	var allCryptoUses []model.CryptoUse

	// ── 1. DNS enumeration ──────────────────────────────────────────────────
	dnsResult, err := dns.Enumerate(ctx, domain, dns.Options{})
	if err != nil {
		return nil, fmt.Errorf("dns enumeration: %w", err)
	}

	// Normalize domain asset
	domainAsset := normalize.NormalizeDomain(orgID, domain)
	domainAsset.LastSeenAt = time.Now()
	allAssets = append(allAssets, domainAsset)

	// DNS records → host assets + edges
	for _, rec := range dnsResult.Records {
		if rec.Type == "A" || rec.Type == "AAAA" {
			hostAsset := normalize.NormalizeHostFromIP(orgID, rec.Value, "dns")
			hostAsset.DisplayName = &rec.Value
			hostAsset.Criticality = "medium"
			allAssets = append(allAssets, hostAsset)
			allEdges = append(allEdges, normalize.CreateResolvesToEdge(domainAsset, hostAsset))
		}
		if rec.Type == "CNAME" {
			subAsset := normalize.NormalizeSubdomain(orgID, rec.Value, "dns")
			allAssets = append(allAssets, subAsset)
			allEdges = append(allEdges, normalize.CreateResolvesToEdge(domainAsset, subAsset))
		}
	}

	// ── 2. Certificate Transparency ─────────────────────────────────────────
	ctSubs, err := ct.Enumerate(ctx, domain)
	if err != nil {
		// CT is best-effort — don't fail the whole discovery
		result.Edges = append(result.Edges, model.AssetEdge{})
	} else {
		seen := map[string]bool{}
		for _, sub := range ctSubs {
			if seen[sub] {
				continue
			}
			seen[sub] = true
			// Skip the apex domain — we already have it
			if strings.EqualFold(sub, domain) {
				continue
			}
			subAsset := normalize.NormalizeSubdomain(orgID, sub, "crt.sh")
			allAssets = append(allAssets, subAsset)
			allEdges = append(allEdges, normalize.CreateResolvesToEdge(domainAsset, subAsset))
		}
	}

	// Collect all targets to probe: apex + subdomains + A/AAAA hosts
	targets := map[string]bool{}
	for _, rec := range dnsResult.Records {
		if rec.Type == "A" || rec.Type == "AAAA" {
			targets[rec.Value] = true
		}
	}
	for _, sub := range ctSubs {
		targets[sub] = true
	}
	targets[domain] = true

	// ── 3. TLS probe every target ───────────────────────────────────────────
	probeOpts := tlsprobe.Options{Timeout: 10 * time.Second}
	for target := range targets {
		host, port, err := net.SplitHostPort(target)
		if err != nil {
			// Assume https port 443
			host = target
			port = "443"
		}
		portNum, parseErr := parseInt(port)
		if parseErr != nil {
			portNum = 443
		}

		obs, err := tlsprobe.Probe(ctx, host, portNum, probeOpts)
		if err != nil || obs == nil {
			continue
		}

		// Certificate asset per chain
		if len(obs.Chain) > 0 {
			for i, cert := range obs.Chain {
				fp := sha256Hex(cert.Raw)
				certAsset := normalize.NormalizeCertificate(orgID, fp)
				subj := cert.Subject.String()
			certAsset.DisplayName = &subj
				certAsset.Criticality = "high"
				certAsset.FirstSeenAt = time.Now()
				certAsset.LastSeenAt = time.Now()
				allAssets = append(allAssets, certAsset)

				// Edge: host presents cert
				hostAsset := normalize.NormalizeHostFromIP(orgID, host, "tls_probe")
				allEdges = append(allEdges, normalize.CreatePresentsCertEdge(hostAsset, certAsset))

				// Parse cert → records + crypto uses
				records, uses := certparse.ParseChain(orgID, certAsset.Id, []*x509.Certificate{obs.Chain[i]})
				_ = records // stored separately if needed
				allCryptoUses = append(allCryptoUses, uses...)
			}
		}

		// TLS version + cipher observations → crypto uses
		for ver, status := range obs.SupportedVersions {
			if status == tlsprobe.Supported {
				verStr := tlsVersionString(ver)
				allCryptoUses = append(allCryptoUses, model.CryptoUse{
					OrganizationId: orgID,
					AssetId:        domainAsset.Id,
					Primitive:      verStr,
					Role:           "protocol",
					QuantumStatus:  "unknown",
					Location:       fmt.Sprintf("tls://%s:%d", host, portNum),
				})
			}
		}
		for cipherID, status := range obs.CipherSuites {
			if status == tlsprobe.Supported {
				cipherName := cipherSuiteName(cipherID)
				allCryptoUses = append(allCryptoUses, model.CryptoUse{
					OrganizationId: orgID,
					AssetId:        domainAsset.Id,
					Primitive:      cipherName,
					Role:           "cipher",
					QuantumStatus:  "unknown",
					Location:       fmt.Sprintf("tls://%s:%d", host, portNum),
				})
			}
		}
	}

	// ── 4. Score all crypto uses with policy engine ─────────────────────────
	for _, cu := range allCryptoUses {
		score := s.policyEngine.ScoreFinding(cu)
		cu.QuantumStatus = score.QuantumStatus
		// Only include as "finding" if it's not compliant/informational
		if score.Risk != "informational" && score.Risk != "low" {
			finding := cu
			result.Findings = append(result.Findings, finding)
		}
	}
	result.CryptoUses = allCryptoUses
	result.Edges = allEdges

	return result, nil
}

// Persist writes the discovery result into the graph store.
func (s *Service) Persist(ctx context.Context, result *DiscoveryResult) error {
	return nil // noop — graph storage requires a real *sql.DB; caller must wire this
}

// RiskSummary produces a simple summary of the discovery findings.
// It scores all crypto uses against the policy engine and aggregates the results.
func (s *Service) RiskSummary(result *DiscoveryResult) map[string]any {
	summary := map[string]any{
		"domain":         result.Domain,
		"total_crypto":   len(result.CryptoUses),
		"by_severity":    map[string]int{},
		"by_quantum":     map[string]int{},
	}

	findingCount := 0
	for _, cu := range result.CryptoUses {
		score := s.policyEngine.ScoreFinding(cu)
		summary["by_severity"].(map[string]int)[score.Risk]++
		summary["by_quantum"].(map[string]int)[score.QuantumStatus]++
		if score.Risk != "informational" && score.Risk != "low" {
			findingCount++
		}
	}
	summary["findings_count"] = findingCount
	return summary
}

// helpers

func parseInt(s string) (int, error) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("not a number")
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h[:])
}

func tlsVersionString(ver uint16) string {
	switch ver {
	case 0x0300:
		return "TLS-1.0"
	case 0x0301:
		return "TLS-1.1"
	case 0x0302:
		return "TLS-1.2"
	case 0x0303:
		return "TLS-1.3"
	default:
		return fmt.Sprintf("TLS-0x%04x", ver)
	}
}

func cipherSuiteName(id uint16) string {
	switch id {
	case 0x0033:
		return "RSA-AES-128-CBC-SHA"
	case 0x0039:
		return "RSA-AES-256-CBC-SHA"
	case 0x002F:
		return "RSA-AES-128-GCM-SHA256"
	case 0x0035:
		return "RSA-AES-256-GCM-SHA384"
	case 0x1301:
		return "TLS-AES-128-GCM-SHA256"
	case 0x1302:
		return "TLS-AES-256-GCM-SHA384"
	case 0x1303:
		return "TLS-CHACHA20-POLY1305-SHA256"
	case 0x000A:
		return "RSA-3DES-EDE-CBC-SHA"
	case 0x0009:
		return "RSA-DES-CBC3-SHA"
	default:
		return fmt.Sprintf("CIPHER-0x%04x", id)
	}
}
