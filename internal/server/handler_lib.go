package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/psycho-prince/pqc-sdk/internal/entitlement"
)

// AuthResult holds the outcome of an authentication attempt.
type AuthResult struct {
	OrgID string
	Err   error
}

// AuthenticateRequest is the extracted, testable auth check.
// It validates the Bearer token and returns the orgID or an error.
func AuthenticateRequest(r *http.Request) AuthResult {
	orgID, err := authenticate(r)
	if err != nil {
		return AuthResult{Err: err}
	}
	return AuthResult{OrgID: orgID}
}

// EntitlementCheckResult holds the outcome of an entitlement feature check.
type EntitlementCheckResult struct {
	Enabled bool
	Err     error
}

// CheckEntitlement verifies the org is entitled to the named feature.
func CheckEntitlement(ctx context.Context, orgID, feature string, fc entitlement.FeatureChecker) EntitlementCheckResult {
	if fc == nil {
		return EntitlementCheckResult{Err: fmt.Errorf("entitlement checks unavailable")}
	}
	enabled, err := fc.IsEnabled(ctx, orgID, feature)
	if err != nil {
		return EntitlementCheckResult{Err: fmt.Errorf("entitlement check failed: %w", err)}
	}
	return EntitlementCheckResult{Enabled: enabled}
}

// ParseJSONBody decodes the request body into the target struct.
// Returns an error string suitable for 400 responses on failure.
func ParseJSONBody(r *http.Request, target interface{}) (err error) {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(target)
}

// BadRequest writes a 400 JSON error response.
func BadRequest(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]interface{}{"error": msg})
}

// MethodNotAllowed writes a 405 JSON error response.
func MethodNotAllowed(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusMethodNotAllowed)
	json.NewEncoder(w).Encode(map[string]interface{}{"error": "Method Not Allowed"})
}

// Unauthorized writes a 401 JSON error response.
func Unauthorized(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]interface{}{"error": "Unauthorized"})
}

// Forbidden writes a 403 JSON error response.
func Forbidden(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(map[string]interface{}{"error": msg})
}

// InternalError writes a 500 JSON error response.
func InternalError(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	json.NewEncoder(w).Encode(map[string]interface{}{"error": msg})
}

// JSONResponse writes a 200 JSON response with the given payload.
func JSONResponse(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(payload)
}

// ValidateOnlyPOST ensures the request method is POST, else 405.
func ValidateOnlyPOST(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		MethodNotAllowed(w)
		return false
	}
	return true
}

// ValidateBodySize limits request body size.
func ValidateBodySize(w http.ResponseWriter, r *http.Request, maxBytes int64) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
}

// GitHubScanRequest represents the POST /v1/connectors/github/scan body.
type GitHubScanRequest struct {
	Owner string `json:"owner"`
	Repo  string `json:"repo"`
}

// ValidateGitHubScanRequest checks the request fields are populated.
func ValidateGitHubScanRequest(req GitHubScanRequest) error {
	if req.Owner == "" || req.Repo == "" {
		return fmt.Errorf("owner and repo are required")
	}
	return nil
}

// AWSScanRequest represents the POST /v1/connectors/aws/scan body.
type AWSScanRequest struct {
	AccountID string   `json:"accountId"`
	Regions   []string `json:"regions"`
}

// ValidateAWSScanRequest checks the request fields.
func ValidateAWSScanRequest(req AWSScanRequest) error {
	if req.AccountID == "" {
		return fmt.Errorf("accountId is required")
	}
	if len(req.Regions) == 0 {
		return fmt.Errorf("at least one region is required")
	}
	return nil
}
