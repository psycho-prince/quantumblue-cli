package github

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"fmt"

	"github.com/psycho-prince/pqc-sdk/internal/model"
)

type FakeFeatureChecker struct {
	Enabled map[string]bool
	Err     error
}

func (f *FakeFeatureChecker) IsEnabled(ctx context.Context, orgID, feature string) (bool, error) {
	if f.Err != nil {
		return false, f.Err
	}
	return f.Enabled[orgID+":"+feature], nil
}

func TestGithubConnector_Discover_Gated(t *testing.T) {
	// Not entitled
	cfg := Config{Organization: "org-1", Owner: "o", Repo: "r"}
	checker := &FakeFeatureChecker{Enabled: map[string]bool{"org-1:github_connector": false}}
	c := NewGithubConnector(cfg, checker)
	_, _, err := c.Discover(context.Background())
	if err == nil || !strings.Contains(err.Error(), "not entitled") {
		t.Fatalf("Expected not entitled error, got %v", err)
	}

	// Checker error
	checker.Err = fmt.Errorf("db error")
	_, _, err = c.Discover(context.Background())
	if err == nil || !strings.Contains(err.Error(), "entitlement check failed: db error") {
		t.Fatalf("Expected db error, got %v", err)
	}
}

func TestGithubConnector_Discover(t *testing.T) {
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)

	files := map[string]string{
		"repo-name-sha/main.go": `package main
import "crypto/rsa"
func main() {
    _ = rsa.PrivateKey{}
}
`,
		"repo-name-sha/README.md": "Hello world",
	}

	for name, body := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0600,
			Size: int64(len(body)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	gzw.Close()

	tarballBytes := buf.Bytes()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/test-org/test-repo/tarball" {
			w.Header().Set("Content-Type", "application/x-gzip")
			w.Write(tarballBytes)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	cfg := Config{
		Token:        "fake-token",
		Organization: "org-123",
		Owner:        "test-org",
		Repo:         "test-repo",
		BaseURL:      ts.URL,
	}

	// Entitled!
	checker := &FakeFeatureChecker{Enabled: map[string]bool{"org-123:github_connector": true}}
	connector := NewGithubConnector(cfg, checker)
	
	assets, edges, err := connector.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}

	var repoAsset *model.Asset
	filesFound := make(map[string]*model.Asset)

	for i, a := range assets {
		if a.Kind == "repository" {
			repoAsset = &assets[i]
		} else if a.Kind == "file" {
			filesFound[a.Identifier] = &assets[i]
		}
	}

	if repoAsset == nil {
		t.Fatal("Expected to find a repository asset")
	}
	if repoAsset.Identifier != "github.com/test-org/test-repo" {
		t.Errorf("Unexpected repo identifier: %s", repoAsset.Identifier)
	}

	mainGoAsset, ok := filesFound["github.com/test-org/test-repo/main.go"]
	if !ok {
		t.Fatal("Expected to find main.go asset")
	}

	if !strings.Contains(string(mainGoAsset.Metadata), "crypto/rsa") {
		t.Errorf("Expected to find crypto/rsa finding in main.go metadata, got %s", mainGoAsset.Metadata)
	}

	foundEdge := false
	for _, e := range edges {
		if e.FromAssetId == repoAsset.Id && e.ToAssetId == mainGoAsset.Id && e.Relation == "contains" {
			foundEdge = true
			break
		}
	}
	if !foundEdge {
		t.Errorf("Expected contains edge from repo to main.go")
	}
}
