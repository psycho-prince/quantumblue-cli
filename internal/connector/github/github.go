package github

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/psycho-prince/pqc-sdk/internal/model"
	"github.com/psycho-prince/pqc-sdk/internal/scanner"
)

type Config struct {
	Token        string
	Organization string
	RepoName     string
	BaseURL      string // For testing
}

type GithubConnector struct {
	config Config
	client *http.Client
}

func NewGithubConnector(config Config) *GithubConnector {
	if config.BaseURL == "" {
		config.BaseURL = "https://api.github.com"
	}
	return &GithubConnector{config: config, client: &http.Client{}}
}

func (c *GithubConnector) Name() string {
	return "github"
}

func (c *GithubConnector) Discover(ctx context.Context) ([]model.Asset, []model.AssetEdge, error) {
	var assets []model.Asset
	var edges []model.AssetEdge

	repoAsset := model.Asset{
		Id:             uuid.New().String(),
		OrganizationId: c.config.Organization,
		Kind:           "repository",
		Identifier:     fmt.Sprintf("github.com/%s", c.config.RepoName),
		Source:         "github",
		Criticality:    "unknown",
		FirstSeenAt:    time.Now(),
		LastSeenAt:     time.Now(),
		Active:         true,
	}
	repoAsset.Metadata, _ = json.Marshal(map[string]string{"name": c.config.RepoName})
	assets = append(assets, repoAsset)

	tmpDir, err := os.MkdirTemp("", "qb-github-")
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(tmpDir)

	// Fetch tarball via REST API
	url := fmt.Sprintf("%s/repos/%s/tarball", c.config.BaseURL, c.config.RepoName)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
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

	// Extract tar.gz
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

		// GitHub tarballs have a top-level directory like repo-name-commitsha/
		// We skip the first directory component
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
				Id:             uuid.New().String(),
				OrganizationId: c.config.Organization,
				Kind:           "file",
				Identifier:     fmt.Sprintf("github.com/%s/%s", c.config.RepoName, relPath),
				Source:         "github",
				Criticality:    "low",
				FirstSeenAt:    time.Now(),
				LastSeenAt:     time.Now(),
				Active:         true,
			}
			
			edges = append(edges, model.AssetEdge{
				Id:          uuid.New().String(),
				FromAssetId: repoAsset.Id,
				ToAssetId:   fileAsset.Id,
				Relation:    "contains",
				Confidence:  1.0,
				CreatedAt:   time.Now(),
			})

			findingsJson := []byte("{}")
			if strings.HasSuffix(target, ".go") {
				goScanner := scanner.NewGoScanner()
				findings, err := goScanner.Scan(target)
				if err == nil && len(findings) > 0 {
					findingsJson, _ = json.Marshal(findings)
				}
			}

			fileAsset.Metadata, _ = json.Marshal(map[string]interface{}{
				"path":     relPath,
				"findings": json.RawMessage(findingsJson),
			})
			assets = append(assets, fileAsset)
		}
	}

	return assets, edges, nil
}
