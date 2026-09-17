package server

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"

	"github.com/psycho-prince/pqc-sdk/internal/entitlement"
	"github.com/psycho-prince/pqc-sdk/internal/model"
)

// ─── Test database setup ─────────────────────────────────────────────────────

// testDB wraps an in-memory SQLite database for testing server handlers.
// Since server_test.go is in package server, it can directly set the
// package-level db variable that authenticate() uses.
type testDB struct {
	db *sql.DB
}

func newTestDB(t *testing.T) *testDB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("failed to open test database: %v", err)
	}

	// Create tables
	_, err = db.Exec(`
		CREATE TABLE ApiKey (
			id INTEGER PRIMARY KEY,
			keyHash TEXT NOT NULL UNIQUE,
			organizationId TEXT NOT NULL,
			revokedAt TIMESTAMP
		);
		CREATE TABLE Entitlement (
			id TEXT PRIMARY KEY,
			organizationId TEXT NOT NULL UNIQUE,
			planCode TEXT NOT NULL DEFAULT 'free',
			source TEXT NOT NULL,
			maxDomains INTEGER NOT NULL DEFAULT 1,
			maxAssets INTEGER NOT NULL DEFAULT 50,
			scansPerMonth INTEGER NOT NULL DEFAULT 3,
			features TEXT NOT NULL DEFAULT '{}'
		);
		CREATE TABLE AuditEvent (
			id TEXT,
			organizationId TEXT,
			action TEXT,
			details TEXT,
			createdAt TIMESTAMP
		);
	`)
	if err != nil {
		t.Fatalf("failed to create test tables: %v", err)
	}

	return &testDB{db: db}
}

// setDBForTest directly sets the package-level db variable for testing.
// This bypasses InitDB's sync.Once to allow test databases.
func (td *testDB) setDB() {
	db = td.db
}

// close closes the test database and resets the package-level db to nil.
func (td *testDB) close() {
	td.setDB()
	td.db.Close()
}

func (td *testDB) insertApiKey(t *testing.T, rawKey, orgID string, revoked bool) {
	t.Helper()
	hash := hashKey(rawKey)
	var revokedVal interface{}
	if revoked {
		revokedVal = "2024-01-01T00:00:00Z"
	}
	_, err := td.db.Exec(`INSERT INTO ApiKey (keyHash, organizationId, revokedAt) VALUES (?, ?, ?)`,
		hash, orgID, revokedVal)
	if err != nil {
		t.Fatalf("failed to insert test API key: %v", err)
	}
}

func (td *testDB) insertEntitlement(t *testing.T, orgID string, e model.Entitlement) {
	t.Helper()
	featuresJSON, _ := json.Marshal(e.Features)
	id := fmt.Sprintf("test-entitlement-%s", orgID)
	_, err := td.db.Exec(`INSERT INTO Entitlement (id, organizationId, planCode, source, maxDomains, maxAssets, scansPerMonth, features) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		id, orgID, e.PlanCode, e.Source, e.MaxDomains, e.MaxAssets, e.ScansPerMonth, string(featuresJSON))
	if err != nil {
		t.Fatalf("failed to insert test entitlement: %v", err)
	}
}

func (td *testDB) clearAuditEvents(t *testing.T) {
	t.Helper()
	_, err := td.db.Exec(`DELETE FROM AuditEvent`)
	if err != nil {
		t.Fatalf("failed to clear audit events: %v", err)
	}
}

func (td *testDB) getAuditCalls(t *testing.T) []map[string]interface{} {
	t.Helper()
	rows, err := td.db.Query(`SELECT organizationId, action, details FROM AuditEvent`)
	if err != nil {
		t.Fatalf("failed to query audit events: %v", err)
	}
	defer rows.Close()

	var calls []map[string]interface{}
	for rows.Next() {
		var orgID, action, detailsStr string
		if err := rows.Scan(&orgID, &action, &detailsStr); err != nil {
			t.Fatalf("failed to scan audit event: %v", err)
		}
		var details map[string]interface{}
		json.Unmarshal([]byte(detailsStr), &details)
		calls = append(calls, map[string]interface{}{
			"organizationId": orgID,
			"action":         action,
			"details":        details,
		})
	}
	return calls
}

func (td *testDB) reset(t *testing.T) {
	t.Helper()
	_, err := td.db.Exec(`DELETE FROM ApiKey`)
	if err != nil {
		t.Fatalf("failed to reset ApiKey: %v", err)
	}
	_, err = td.db.Exec(`DELETE FROM Entitlement`)
	if err != nil {
		t.Fatalf("failed to reset Entitlement: %v", err)
	}
	_, err = td.db.Exec(`DELETE FROM AuditEvent`)
	if err != nil {
		t.Fatalf("failed to reset AuditEvent: %v", err)
	}
}

// ─── Hash helper ─────────────────────────────────────────────────────────────

func hashKey(rawKey string) string {
	h := sha256.Sum256([]byte(rawKey))
	return hex.EncodeToString(h[:])
}

// ─── FeatureChecker helpers ─────────────────────────────────────────────────

func featureCheckerFromTestDB(td *testDB) entitlement.FeatureChecker {
	return entitlement.NewDBFeatureChecker(entitlement.NewDBEntitlementStore(td.db))
}

// failingFeatureChecker is a FeatureChecker that always returns an error.
type failingFeatureChecker struct {
	err error
}

func (f *failingFeatureChecker) IsEnabled(ctx context.Context, orgID, feature string) (bool, error) {
	return false, f.err
}

// ─── Handler registration (testable) ─────────────────────────────────────────

// registerAllHandlers registers all daemon handlers on the given ServeMux.
// This mirrors the handler registration in StartServer for testability.
func registerAllHandlers(mux *http.ServeMux, featureChecker entitlement.FeatureChecker) {
	// /health
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "ok",
		})
	})

	// /v1/keys
	mux.HandleFunc("/v1/keys", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusMethodNotAllowed)
			fmt.Fprint(w, `{"error": "Method Not Allowed"}`)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 10<<20)
		orgID, err := authenticate(r)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error": "Unauthorized"}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"organization": orgID,
		})
	})

	// /v1/connectors/github/scan
	mux.HandleFunc("/v1/connectors/github/scan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusMethodNotAllowed)
			fmt.Fprint(w, `{"error": "Method Not Allowed"}`)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 10<<20)
		orgID, err := authenticate(r)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error": "Unauthorized"}`)
			return
		}

		if featureChecker != nil {
			enabled, err := featureChecker.IsEnabled(r.Context(), orgID, "github_connector")
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, `{"error": "Internal server error during entitlement check"}`)
				return
			}
			if !enabled {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprint(w, `{"error": "Forbidden: Organization is not entitled to github_connector"}`)
				return
			}
		} else {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"error": "Forbidden: Entitlement checks unavailable"}`)
			return
		}

		var req struct {
			Owner string `json:"owner"`
			Repo  string `json:"repo"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error": "Invalid request"}`)
			return
		}
		if req.Owner == "" || req.Repo == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error": "owner and repo are required"}`)
			return
		}

		LogAuditEvent(orgID, "CONNECTOR_SCAN", map[string]interface{}{
			"connector": "github",
			"owner":     req.Owner,
			"repo":      req.Repo,
			"assets":    0,
			"edges":     0,
		})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"organization": orgID,
			"assets":       []interface{}{},
			"edges":        []interface{}{},
		})
	})

	// /v1/connectors/aws/scan
	mux.HandleFunc("/v1/connectors/aws/scan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusMethodNotAllowed)
			fmt.Fprint(w, `{"error": "Method Not Allowed"}`)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 10<<20)
		orgID, err := authenticate(r)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error": "Unauthorized"}`)
			return
		}

		if featureChecker != nil {
			enabled, err := featureChecker.IsEnabled(r.Context(), orgID, "aws_connector")
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, `{"error": "Internal server error during entitlement check"}`)
				return
			}
			if !enabled {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				fmt.Fprint(w, `{"error": "Forbidden: Organization is not entitled to aws_connector"}`)
				return
			}
		} else {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"error": "Forbidden: Entitlement checks unavailable"}`)
			return
		}

		var req struct {
			RoleARN    string   `json:"roleArn"`
			ExternalID string   `json:"externalId"`
			Regions    []string `json:"regions"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error": "Invalid request"}`)
			return
		}
		if req.RoleARN == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"error": "roleArn is required"}`)
			return
		}

		LogAuditEvent(orgID, "CONNECTOR_SCAN", map[string]interface{}{
			"connector": "aws",
			"role_arn":  req.RoleARN,
			"assets":    0,
			"edges":     0,
		})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"organization": orgID,
			"assets":       []interface{}{},
			"edges":        []interface{}{},
		})
	})
}

// ─── Tests ───────────────────────────────────────────────────────────────────

func setupTest(t *testing.T) *testDB {
	td := newTestDB(t)
	td.setDB()
	return td
}

func TestAuthenticate_MissingHeader(t *testing.T) {
	td := setupTest(t)
	defer td.db.Close()

	// Insert test data
	td.insertApiKey(t, "test-key", "org-123", false)
	td.insertEntitlement(t, "org-123", model.Entitlement{
		OrganizationId: "org-123",
		Features:       model.FeaturesFromString(`{"github_connector":true}`),
	})

	mux := http.NewServeMux()
	registerAllHandlers(mux, featureCheckerFromTestDB(td))

	server := httptest.NewServer(mux)
	defer server.Close()

	resp, err := http.Post(server.URL+"/v1/connectors/github/scan",
		"application/json",
		strings.NewReader(`{"owner":"o","repo":"r"}`))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for missing header, got %d", resp.StatusCode)
	}
}

func TestAuthenticate_MalformedHeader(t *testing.T) {
	td := setupTest(t)
	defer td.db.Close()

	td.insertApiKey(t, "test-key", "org-123", false)
	td.insertEntitlement(t, "org-123", model.Entitlement{
		OrganizationId: "org-123",
		Features:       model.FeaturesFromString(`{"github_connector":true}`),
	})

	mux := http.NewServeMux()
	registerAllHandlers(mux, featureCheckerFromTestDB(td))

	server := httptest.NewServer(mux)
	defer server.Close()

	req, _ := http.NewRequest("POST",
		server.URL+"/v1/connectors/github/scan",
		strings.NewReader(`{"owner":"o","repo":"r"}`))
	req.Header.Set("Authorization", "Basic dGVzdA==")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for malformed header, got %d", resp.StatusCode)
	}
}

func TestAuthenticate_EmptyBearer(t *testing.T) {
	td := setupTest(t)
	defer td.db.Close()

	td.insertApiKey(t, "test-key", "org-123", false)
	td.insertEntitlement(t, "org-123", model.Entitlement{
		OrganizationId: "org-123",
		Features:       model.FeaturesFromString(`{"github_connector":true}`),
	})

	mux := http.NewServeMux()
	registerAllHandlers(mux, featureCheckerFromTestDB(td))

	server := httptest.NewServer(mux)
	defer server.Close()

	req, _ := http.NewRequest("POST",
		server.URL+"/v1/connectors/github/scan",
		strings.NewReader(`{"owner":"o","repo":"r"}`))
	req.Header.Set("Authorization", "Bearer ")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for empty bearer, got %d", resp.StatusCode)
	}
}

func TestAuthenticate_InvalidKey(t *testing.T) {
	td := setupTest(t)
	defer td.db.Close()

	td.insertApiKey(t, "test-key", "org-123", false)
	td.insertEntitlement(t, "org-123", model.Entitlement{
		OrganizationId: "org-123",
		Features:       model.FeaturesFromString(`{"github_connector":true}`),
	})

	mux := http.NewServeMux()
	registerAllHandlers(mux, featureCheckerFromTestDB(td))

	server := httptest.NewServer(mux)
	defer server.Close()

	req, _ := http.NewRequest("POST",
		server.URL+"/v1/connectors/github/scan",
		strings.NewReader(`{"owner":"o","repo":"r"}`))
	req.Header.Set("Authorization", "Bearer nonexistent-key-12345")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for invalid key, got %d", resp.StatusCode)
	}
}

func TestAuthenticate_RevokedKey(t *testing.T) {
	td := setupTest(t)
	defer td.db.Close()

	// Insert a revoked key
	td.insertApiKey(t, "revoked-key", "org-456", true)
	td.insertEntitlement(t, "org-456", model.Entitlement{
		OrganizationId: "org-456",
		Features:       model.FeaturesFromString(`{}`),
	})

	mux := http.NewServeMux()
	registerAllHandlers(mux, featureCheckerFromTestDB(td))

	server := httptest.NewServer(mux)
	defer server.Close()

	req, _ := http.NewRequest("POST",
		server.URL+"/v1/connectors/github/scan",
		strings.NewReader(`{"owner":"o","repo":"r"}`))
	req.Header.Set("Authorization", "Bearer revoked-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 for revoked key, got %d", resp.StatusCode)
	}
}

func TestAuthenticate_ValidKey_Succeeds(t *testing.T) {
	td := newTestDB(t)
	defer td.db.Close()
	td.setDB()

	td.insertApiKey(t, "valid-key", "org-123", false)
	td.insertEntitlement(t, "org-123", model.Entitlement{
		OrganizationId: "org-123",
		Features:       model.FeaturesFromString(`{"github_connector":true}`),
	})

	mux := http.NewServeMux()
	registerAllHandlers(mux, featureCheckerFromTestDB(td))

	server := httptest.NewServer(mux)
	defer server.Close()

	req, _ := http.NewRequest("POST",
		server.URL+"/v1/connectors/github/scan",
		strings.NewReader(`{"owner":"o","repo":"r"}`))
	req.Header.Set("Authorization", "Bearer valid-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("expected 200 for valid key, got %d: %s", resp.StatusCode, string(body))
	}
}

func TestEntitlement_GitHubDisabled_Returns403(t *testing.T) {
	td := newTestDB(t)
	defer td.db.Close()
	td.setDB()

	td.insertApiKey(t, "test-key", "org-123", false)
	// Entitlement WITHOUT github_connector
	td.insertEntitlement(t, "org-123", model.Entitlement{
		OrganizationId: "org-123",
		Features:       model.FeaturesFromString(`{"aws_connector":true}`),
	})

	mux := http.NewServeMux()
	registerAllHandlers(mux, featureCheckerFromTestDB(td))

	server := httptest.NewServer(mux)
	defer server.Close()

	req, _ := http.NewRequest("POST",
		server.URL+"/v1/connectors/github/scan",
		strings.NewReader(`{"owner":"o","repo":"r"}`))
	req.Header.Set("Authorization", "Bearer test-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 for disabled GitHub feature, got %d", resp.StatusCode)
	}
}

func TestEntitlement_GitHubEnabled_Succeeds(t *testing.T) {
	td := newTestDB(t)
	defer td.db.Close()
	td.setDB()

	td.insertApiKey(t, "test-key", "org-123", false)
	td.insertEntitlement(t, "org-123", model.Entitlement{
		OrganizationId: "org-123",
		Features:       model.FeaturesFromString(`{"github_connector":true}`),
	})

	mux := http.NewServeMux()
	registerAllHandlers(mux, featureCheckerFromTestDB(td))

	server := httptest.NewServer(mux)
	defer server.Close()

	req, _ := http.NewRequest("POST",
		server.URL+"/v1/connectors/github/scan",
		strings.NewReader(`{"owner":"o","repo":"r"}`))
	req.Header.Set("Authorization", "Bearer test-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 for enabled GitHub feature, got %d", resp.StatusCode)
	}
}

func TestEntitlement_AWSDisabled_Returns403(t *testing.T) {
	td := newTestDB(t)
	defer td.db.Close()
	td.setDB()

	td.insertApiKey(t, "test-key", "org-123", false)
	// Entitlement WITHOUT aws_connector
	td.insertEntitlement(t, "org-123", model.Entitlement{
		OrganizationId: "org-123",
		Features:       model.FeaturesFromString(`{"github_connector":true}`),
	})

	mux := http.NewServeMux()
	registerAllHandlers(mux, featureCheckerFromTestDB(td))

	server := httptest.NewServer(mux)
	defer server.Close()

	req, _ := http.NewRequest("POST",
		server.URL+"/v1/connectors/aws/scan",
		strings.NewReader(`{"roleArn":"arn:aws:iam::123456789012:role/Test"}`))
	req.Header.Set("Authorization", "Bearer test-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 for disabled AWS feature, got %d", resp.StatusCode)
	}
}

func TestEntitlement_CheckerError_Returns500(t *testing.T) {
	td := newTestDB(t)
	defer td.db.Close()
	td.setDB()

	td.insertApiKey(t, "test-key", "org-123", false)
	td.insertEntitlement(t, "org-123", model.Entitlement{
		OrganizationId: "org-123",
		Features:       model.FeaturesFromString(`{"github_connector":true}`),
	})

	fc := &failingFeatureChecker{err: fmt.Errorf("database connection lost")}

	mux := http.NewServeMux()
	registerAllHandlers(mux, fc)

	server := httptest.NewServer(mux)
	defer server.Close()

	req, _ := http.NewRequest("POST",
		server.URL+"/v1/connectors/github/scan",
		strings.NewReader(`{"owner":"o","repo":"r"}`))
	req.Header.Set("Authorization", "Bearer test-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected 500 for checker error, got %d", resp.StatusCode)
	}
}

func TestEntitlement_FailClosed_WhenNilChecker(t *testing.T) {
	td := newTestDB(t)
	defer td.db.Close()
	td.setDB()

	td.insertApiKey(t, "test-key", "org-123", false)
	td.insertEntitlement(t, "org-123", model.Entitlement{
		OrganizationId: "org-123",
		Features:       model.FeaturesFromString(`{"github_connector":true}`),
	})

	mux := http.NewServeMux()
	registerAllHandlers(mux, nil) // nil FeatureChecker → fail-closed

	server := httptest.NewServer(mux)
	defer server.Close()

	req, _ := http.NewRequest("POST",
		server.URL+"/v1/connectors/github/scan",
		strings.NewReader(`{"owner":"o","repo":"r"}`))
	req.Header.Set("Authorization", "Bearer test-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 when featureChecker is nil (fail-closed), got %d", resp.StatusCode)
	}
}

func TestEntitlement_FailClosed_AWS_WhenNilChecker(t *testing.T) {
	td := newTestDB(t)
	defer td.db.Close()
	td.setDB()

	td.insertApiKey(t, "test-key", "org-123", false)
	td.insertEntitlement(t, "org-123", model.Entitlement{
		OrganizationId: "org-123",
		Features:       model.FeaturesFromString(`{"github_connector":true}`),
	})

	mux := http.NewServeMux()
	registerAllHandlers(mux, nil) // nil FeatureChecker → fail-closed

	server := httptest.NewServer(mux)
	defer server.Close()

	req, _ := http.NewRequest("POST",
		server.URL+"/v1/connectors/aws/scan",
		strings.NewReader(`{"roleArn":"arn:aws:iam::123456789012:role/Test"}`))
	req.Header.Set("Authorization", "Bearer test-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 for AWS when featureChecker is nil, got %d", resp.StatusCode)
	}
}

func TestAuditLog_GitHubScan_LogsCorrectly(t *testing.T) {
	td := newTestDB(t)
	defer td.db.Close()
	td.setDB()

	td.clearAuditEvents(t)
	td.insertApiKey(t, "test-key", "org-123", false)
	td.insertEntitlement(t, "org-123", model.Entitlement{
		OrganizationId: "org-123",
		Features:       model.FeaturesFromString(`{"github_connector":true}`),
	})

	mux := http.NewServeMux()
	registerAllHandlers(mux, featureCheckerFromTestDB(td))

	server := httptest.NewServer(mux)
	defer server.Close()

	req, _ := http.NewRequest("POST",
		server.URL+"/v1/connectors/github/scan",
		strings.NewReader(`{"owner":"psycho-prince","repo":"quantumblue-cli"}`))
	req.Header.Set("Authorization", "Bearer test-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	calls := td.getAuditCalls(t)
	if len(calls) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(calls))
	}

	call := calls[0]
	if call["organizationId"] != "org-123" {
		t.Errorf("expected org-123 in audit, got %v", call["organizationId"])
	}
	if call["action"] != "CONNECTOR_SCAN" {
		t.Errorf("expected CONNECTOR_SCAN, got %v", call["action"])
	}

	details := call["details"].(map[string]interface{})
	if details["connector"] != "github" {
		t.Errorf("expected connector=github, got %v", details["connector"])
	}
	if details["owner"] != "psycho-prince" {
		t.Errorf("expected owner=psycho-prince, got %v", details["owner"])
	}
	if details["repo"] != "quantumblue-cli" {
		t.Errorf("expected repo=quantumblue-cli, got %v", details["repo"])
	}
}

func TestAuditLog_AWSScan_LogsCorrectly(t *testing.T) {
	td := newTestDB(t)
	defer td.db.Close()
	td.setDB()

	td.clearAuditEvents(t)
	td.insertApiKey(t, "test-key", "org-123", false)
	td.insertEntitlement(t, "org-123", model.Entitlement{
		OrganizationId: "org-123",
		Features:       model.FeaturesFromString(`{"aws_connector":true}`),
	})

	mux := http.NewServeMux()
	registerAllHandlers(mux, featureCheckerFromTestDB(td))

	server := httptest.NewServer(mux)
	defer server.Close()

	req, _ := http.NewRequest("POST",
		server.URL+"/v1/connectors/aws/scan",
		strings.NewReader(`{"roleArn":"arn:aws:iam::123456789012:role/Test"}`))
	req.Header.Set("Authorization", "Bearer test-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	calls := td.getAuditCalls(t)
	if len(calls) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(calls))
	}

	call := calls[0]
	if call["action"] != "CONNECTOR_SCAN" {
		t.Errorf("expected CONNECTOR_SCAN, got %v", call["action"])
	}

	details := call["details"].(map[string]interface{})
	if details["connector"] != "aws" {
		t.Errorf("expected connector=aws, got %v", details["connector"])
	}
	if details["role_arn"] != "arn:aws:iam::123456789012:role/Test" {
		t.Errorf("expected role_arn in audit, got %v", details["role_arn"])
	}
}

func TestAWSInput_Validation_RoleARNRequired(t *testing.T) {
	td := newTestDB(t)
	defer td.db.Close()
	td.setDB()

	td.insertApiKey(t, "test-key", "org-123", false)
	td.insertEntitlement(t, "org-123", model.Entitlement{
		OrganizationId: "org-123",
		Features:       model.FeaturesFromString(`{"aws_connector":true}`),
	})

	mux := http.NewServeMux()
	registerAllHandlers(mux, featureCheckerFromTestDB(td))

	server := httptest.NewServer(mux)
	defer server.Close()

	req, _ := http.NewRequest("POST",
		server.URL+"/v1/connectors/aws/scan",
		strings.NewReader(`{"externalId":"test"}`))
	req.Header.Set("Authorization", "Bearer test-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for missing roleArn, got %d", resp.StatusCode)
	}
}

func TestAWSInput_Validation_BadJSON(t *testing.T) {
	td := newTestDB(t)
	defer td.db.Close()
	td.setDB()

	td.insertApiKey(t, "test-key", "org-123", false)
	td.insertEntitlement(t, "org-123", model.Entitlement{
		OrganizationId: "org-123",
		Features:       model.FeaturesFromString(`{"aws_connector":true}`),
	})

	mux := http.NewServeMux()
	registerAllHandlers(mux, featureCheckerFromTestDB(td))

	server := httptest.NewServer(mux)
	defer server.Close()

	req, _ := http.NewRequest("POST",
		server.URL+"/v1/connectors/aws/scan",
		strings.NewReader(`{invalid json}`))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", resp.StatusCode)
	}
}

func TestAWSInput_Validation_MethodNotAllowed(t *testing.T) {
	td := newTestDB(t)
	defer td.db.Close()
	td.setDB()

	td.insertApiKey(t, "test-key", "org-123", false)
	td.insertEntitlement(t, "org-123", model.Entitlement{
		OrganizationId: "org-123",
		Features:       model.FeaturesFromString(`{"aws_connector":true}`),
	})

	mux := http.NewServeMux()
	registerAllHandlers(mux, featureCheckerFromTestDB(td))

	server := httptest.NewServer(mux)
	defer server.Close()

	req, _ := http.NewRequest("GET", server.URL+"/v1/connectors/aws/scan", nil)
	req.Header.Set("Authorization", "Bearer test-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for GET, got %d", resp.StatusCode)
	}
}

func TestGitHubInput_Validation_BadJSON(t *testing.T) {
	td := newTestDB(t)
	defer td.db.Close()
	td.setDB()

	td.insertApiKey(t, "test-key", "org-123", false)
	td.insertEntitlement(t, "org-123", model.Entitlement{
		OrganizationId: "org-123",
		Features:       model.FeaturesFromString(`{"github_connector":true}`),
	})

	mux := http.NewServeMux()
	registerAllHandlers(mux, featureCheckerFromTestDB(td))

	server := httptest.NewServer(mux)
	defer server.Close()

	req, _ := http.NewRequest("POST",
		server.URL+"/v1/connectors/github/scan",
		strings.NewReader(`{invalid json}`))
	req.Header.Set("Authorization", "Bearer test-key")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", resp.StatusCode)
	}
}

func TestGitHubInput_Validation_MissingFields(t *testing.T) {
	td := newTestDB(t)
	defer td.db.Close()
	td.setDB()

	td.insertApiKey(t, "test-key", "org-123", false)
	td.insertEntitlement(t, "org-123", model.Entitlement{
		OrganizationId: "org-123",
		Features:       model.FeaturesFromString(`{"github_connector":true}`),
	})

	mux := http.NewServeMux()
	registerAllHandlers(mux, featureCheckerFromTestDB(td))

	server := httptest.NewServer(mux)
	defer server.Close()

	// Missing repo
	req, _ := http.NewRequest("POST",
		server.URL+"/v1/connectors/github/scan",
		strings.NewReader(`{"owner":"psycho-prince"}`))
	req.Header.Set("Authorization", "Bearer test-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 for missing repo, got %d", resp.StatusCode)
	}
}

func TestHealthEndpoint(t *testing.T) {
	td := newTestDB(t)
	defer td.db.Close()
	td.setDB()

	mux := http.NewServeMux()
	registerAllHandlers(mux, nil)

	server := httptest.NewServer(mux)
	defer server.Close()

	resp, err := http.Get(server.URL + "/health")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 for health, got %d", resp.StatusCode)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if body["status"] != "ok" {
		t.Errorf("expected status=ok, got %v", body["status"])
	}
}

func TestMultipleOrgs_Isolated(t *testing.T) {
	td := newTestDB(t)
	defer td.db.Close()
	td.setDB()

	// org-1: github_connector only
	td.insertApiKey(t, "org1-key", "org-1", false)
	td.insertEntitlement(t, "org-1", model.Entitlement{
		OrganizationId: "org-1",
		Features:       model.FeaturesFromString(`{"github_connector":true}`),
	})

	// org-2: aws_connector only
	td.insertApiKey(t, "org2-key", "org-2", false)
	td.insertEntitlement(t, "org-2", model.Entitlement{
		OrganizationId: "org-2",
		Features:       model.FeaturesFromString(`{"aws_connector":true}`),
	})

	mux := http.NewServeMux()
	registerAllHandlers(mux, featureCheckerFromTestDB(td))

	server := httptest.NewServer(mux)
	defer server.Close()

	// org-1 → GitHub (should succeed)
	req, _ := http.NewRequest("POST",
		server.URL+"/v1/connectors/github/scan",
		strings.NewReader(`{"owner":"o","repo":"r"}`))
	req.Header.Set("Authorization", "Bearer org1-key")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("org-1 GitHub: expected 200, got %d", resp.StatusCode)
	}

	// org-1 → AWS (should fail — not entitled)
	req, _ = http.NewRequest("POST",
		server.URL+"/v1/connectors/aws/scan",
		strings.NewReader(`{"roleArn":"arn:aws:iam::123456789012:role/Test"}`))
	req.Header.Set("Authorization", "Bearer org1-key")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("org-1 AWS: expected 403, got %d", resp.StatusCode)
	}

	// org-2 → GitHub (should fail — not entitled)
	req, _ = http.NewRequest("POST",
		server.URL+"/v1/connectors/github/scan",
		strings.NewReader(`{"owner":"o","repo":"r"}`))
	req.Header.Set("Authorization", "Bearer org2-key")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("org-2 GitHub: expected 403, got %d", resp.StatusCode)
	}

	// org-2 → AWS (should succeed)
	req, _ = http.NewRequest("POST",
		server.URL+"/v1/connectors/aws/scan",
		strings.NewReader(`{"roleArn":"arn:aws:iam::123456789012:role/Test"}`))
	req.Header.Set("Authorization", "Bearer org2-key")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("org-2 AWS: expected 200, got %d", resp.StatusCode)
	}
}
