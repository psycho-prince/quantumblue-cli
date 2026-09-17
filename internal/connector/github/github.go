package github

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/psycho-prince/pqc-sdk/internal/entitlement"
	"github.com/psycho-prince/pqc-sdk/internal/model"
	"github.com/psycho-prince/pqc-sdk/internal/scanner"
)

type Config struct {
	Token             string
	Organization      string
	Owner             string
	Repo              string
	BaseURL           string // For testing
	EntitlementBypass bool   // test hook
}

type GithubConnector struct {
	config Config
	client *http.Client
	checker entitlement.FeatureChecker
}

func NewGithubConnector(config Config, checker entitlement.FeatureChecker) *GithubConnector {
	if config.BaseURL == "" {
		config.BaseURL = "https://api.github.com"
	}
	return &GithubConnector{config: config, client: &http.Client{}, checker: checker}
}

func (c *GithubConnector) Name() string {
	return "github"
}

func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (c *GithubConnector) Discover(ctx context.Context) ([]model.Asset, []model.AssetEdge, error) {
	if !c.config.EntitlementBypass && c.checker != nil {
		enabled, err := c.checker.IsEnabled(ctx, c.config.Organization, "github_connector")
		if err != nil {
			return nil, nil, fmt.Errorf("entitlement check failed: %w", err)
		}
		if !enabled {
			return nil, nil, fmt.Errorf("organization %s is not entitled to feature github_connector", c.config.Organization)
		}
	}

	var assets []model.Asset
	var edges []model.AssetEdge

	repoFullName := fmt.Sprintf("%s/%s", c.config.Owner, c.config.Repo)
	repoAsset := model.Asset{
		Id:             generateID(),
		OrganizationId: c.config.Organization,
		Kind:           "repository",
		Identifier:     fmt.Sprintf("github.com/%s", repoFullName),
		Source:         "github",
		Criticality:    "unknown",
		FirstSeenAt:    time.Now(),
		LastSeenAt:     time.Now(),
		Active:         true,
	}

	meta, err := json.Marshal(map[string]string{"name": repoFullName})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal repo metadata: %w", err)
	}
	repoAsset.Metadata = meta
	assets = append(assets, repoAsset)

	tmpDir, err := os.MkdirTemp("", "qb-github-")
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(tmpDir)

	u, err := url.Parse(c.config.BaseURL)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid base URL: %w", err)
	}
	u.Path = filepath.Join(u.Path, "repos", url.PathEscape(c.config.Owner), url.PathEscape(c.config.Repo), "tarball")

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return nil, nil, err
	}
	if c.config.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.config.Token)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to fetch repo tarball: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("github api error: status %d", resp.StatusCode)
	}

	gzr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read gzip: %v", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("tar error: %v", err)
		}

		parts := strings.SplitN(header.Name, "/", 2)
		if len(parts) < 2 || parts[1] == "" {
			continue
		}
		relPath := parts[1]
		target := filepath.Join(tmpDir, relPath)

		if header.Typeflag == tar.TypeDir {
			os.MkdirAll(target, 0755)
			continue
		} else if header.Typeflag == tar.TypeReg {
			os.MkdirAll(filepath.Dir(target), 0755)
			f, err := os.Create(target)
			if err != nil {
				return nil, nil, err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return nil, nil, err
			}
			f.Close()

			fileAsset := model.Asset{
				Id:             generateID(),
				OrganizationId: c.config.Organization,
				Kind:           "file",
				Identifier:     fmt.Sprintf("github.com/%s/%s", repoFullName, relPath),
				Source:         "github",
				Criticality:    "low",
				FirstSeenAt:    time.Now(),
				LastSeenAt:     time.Now(),
				Active:         true,
			}

			edges = append(edges, model.AssetEdge{
				Id:          generateID(),
				FromAssetId: repoAsset.Id,
				ToAssetId:   fileAsset.Id,
				Relation:    "contains",
				Confidence:  1.0,
				CreatedAt:   time.Now(),
			})

			findingsJson := []byte("[]")
			if strings.HasSuffix(target, ".go") {
				goScanner := scanner.NewGoScanner()
				findings, err := goScanner.Scan(target)
				if err == nil && len(findings) > 0 {
					fj, merr := json.Marshal(findings)
					if merr != nil {
						return nil, nil, fmt.Errorf("failed to marshal findings for %s: %w", relPath, merr)
					}
					findingsJson = fj
				}
			}

			fileMeta, err := json.Marshal(map[string]interface{}{
				"path":     relPath,
				"findings": json.RawMessage(findingsJson),
			})
			if err != nil {
				return nil, nil, fmt.Errorf("failed to marshal file metadata: %w", err)
			}
			fileAsset.Metadata = fileMeta

			assets = append(assets, fileAsset)
		}
	}

	return assets, edges, nil
}
