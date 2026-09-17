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
)

func TestGithubConnector_Discover(t *testing.T) {
	// Create a fake tarball
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

	// Mock server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/org/repo/tarball" {
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
		RepoName:     "org/repo",
		BaseURL:      ts.URL,
	}

	connector := NewGithubConnector(cfg)
	assets, edges, err := connector.Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}

	if len(assets) != 3 { // 1 repo + 2 files
		t.Errorf("Expected 3 assets, got %d", len(assets))
	}

	if len(edges) != 2 { // repo->file1, repo->file2
		t.Errorf("Expected 2 edges, got %d", len(edges))
	}

	// Verify that the finding was detected in main.go
	foundFinding := false
	for _, a := range assets {
		if a.Kind == "file" && a.Identifier == "github.com/org/repo/main.go" {
			metadata := string(a.Metadata)
			if strings.Contains(metadata, "crypto/rsa") {
				foundFinding = true
			}
		}
	}
	if !foundFinding {
		t.Errorf("Expected to find crypto/rsa finding in main.go metadata")
	}
}
