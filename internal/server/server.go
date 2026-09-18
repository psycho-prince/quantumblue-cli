package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/psycho-prince/pqc-sdk/internal/crypto"
	"github.com/psycho-prince/pqc-sdk/internal/scanner"
	"github.com/psycho-prince/pqc-sdk/internal/entitlement"
	"github.com/psycho-prince/pqc-sdk/internal/connector/github"
	"github.com/psycho-prince/pqc-sdk/internal/connector/aws"
)

// StartServer initializes the HTTP daemon exposing PQC operations
func StartServer(port, dsn string) error {
	if dsn != "" {
		if err := InitDB(dsn); err != nil {
			return fmt.Errorf("database initialization failed: %w", err)
		}
		fmt.Println("Connected to unified PostgreSQL database")
	}

	var featureChecker entitlement.FeatureChecker
	if db != nil {
		store := entitlement.NewDBEntitlementStore(db)
		featureChecker = entitlement.NewDBFeatureChecker(store)
	}

	// /health
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "ok",
		})
	})

	// /v1/keys
	http.HandleFunc("/v1/keys", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 10<<20)
		orgID, err := authenticate(r)
		if err != nil {
			http.Error(w, `{"error": "Unauthorized"}`, http.StatusUnauthorized)
			return
		}

		provider := crypto.NewFileKeyProvider("")
		err = provider.GenerateKey(orgID)
		if err != nil {
			http.Error(w, "Failed to generate keys", http.StatusInternalServerError)
			return
		}
		
		pkBytes, _ := os.ReadFile(orgID + ".pub")

		LogAuditEvent(orgID, "GENERATE_KEYPAIR", map[string]interface{}{
			"algorithm": "ML-DSA-65",
		})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"organization": orgID,
			"public_key":   pkBytes,
		})
	})

	// /v1/sign
	http.HandleFunc("/v1/sign", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 10<<20)
		orgID, err := authenticate(r)
		if err != nil {
			http.Error(w, `{"error": "Unauthorized"}`, http.StatusUnauthorized)
			return
		}

		var req struct {
			Data []byte `json:"data"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		provider := crypto.NewFileKeyProvider("")
		signature, err := provider.Sign(orgID, req.Data)
		if err != nil {
			http.Error(w, "Signing failed: key not found or error", http.StatusInternalServerError)
			return
		}

		LogAuditEvent(orgID, "SIGN_ENVELOPE", map[string]interface{}{
			"data_length": len(req.Data),
		})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"organization": orgID,
			"signature":    signature,
		})
	})

	// /v1/verify
	http.HandleFunc("/v1/verify", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 10<<20)
		orgID, err := authenticate(r)
		if err != nil {
			http.Error(w, `{"error": "Unauthorized"}`, http.StatusUnauthorized)
			return
		}

		var req struct {
			Data      []byte `json:"data"`
			Signature []byte `json:"signature"`
			PublicKey []byte `json:"public_key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		valid := crypto.VerifyEnvelope(req.Data, req.Signature, req.PublicKey)

		LogAuditEvent(orgID, "VERIFY_ENVELOPE", map[string]interface{}{
			"data_length": len(req.Data),
			"is_valid":    valid,
		})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"organization": orgID,
			"valid":        valid,
		})
	})

	// /v1/cbom
	http.HandleFunc("/v1/cbom", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 10<<20)
		orgID, err := authenticate(r)
		if err != nil {
			http.Error(w, `{"error": "Unauthorized"}`, http.StatusUnauthorized)
			return
		}

		var req struct {
			FilePath   string `json:"file_path"`
			SourceCode string `json:"source_code"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		s := scanner.NewGoScanner()
		var findings []scanner.CBOMItem
		var scanErr error

		if req.SourceCode != "" {
			tmpfile, err := os.CreateTemp("", "scan-*.go")
			if err != nil {
				http.Error(w, "Failed to create temp file", http.StatusInternalServerError)
				return
			}
			defer os.Remove(tmpfile.Name())
			if _, err := tmpfile.Write([]byte(req.SourceCode)); err != nil {
				http.Error(w, "Failed to write temp file", http.StatusInternalServerError)
				return
			}
			tmpfile.Close()
			findings, scanErr = s.Scan(tmpfile.Name())
		} else if req.FilePath != "" {
			findings, scanErr = s.Scan(req.FilePath)
		} else {
			http.Error(w, "Must provide file_path or source_code", http.StatusBadRequest)
			return
		}

		if scanErr != nil {
			http.Error(w, fmt.Sprintf("Scan failed: %v", scanErr), http.StatusInternalServerError)
			return
		}

		LogAuditEvent(orgID, "GENERATE_CBOM", map[string]interface{}{
			"findings_count": len(findings),
		})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"organization": orgID,
			"cbom":         findings,
		})
	})

	// /v1/connectors/github/scan
	http.HandleFunc("/v1/connectors/github/scan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 10<<20)
		orgID, err := authenticate(r)
		if err != nil {
			http.Error(w, `{"error": "Unauthorized"}`, http.StatusUnauthorized)
			return
		}

		if featureChecker != nil {
			enabled, err := featureChecker.IsEnabled(r.Context(), orgID, "github_connector")
			if err != nil {
				http.Error(w, "Internal server error during entitlement check", http.StatusInternalServerError)
				return
			}
			if !enabled {
				http.Error(w, `{"error": "Forbidden: Organization is not entitled to github_connector"}`, http.StatusForbidden)
				return
			}
		} else {
			// If no DB / feature checker is configured, we must fail closed to prevent unpaid scans in prod.
			http.Error(w, `{"error": "Forbidden: Entitlement checks unavailable"}`, http.StatusForbidden)
			return
		}

		var req struct {
			Owner string `json:"owner"`
			Repo  string `json:"repo"`
			Token string `json:"token"` // Optional user-provided token
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		if req.Owner == "" || req.Repo == "" {
			http.Error(w, "owner and repo are required", http.StatusBadRequest)
			return
		}

		cfg := github.Config{
			Organization: orgID,
			Owner:        req.Owner,
			Repo:         req.Repo,
			Token:        req.Token,
		}

		conn := github.NewGithubConnector(cfg, featureChecker)
		assets, edges, err := conn.Discover(r.Context())
		if err != nil {
			http.Error(w, fmt.Sprintf("Connector discovery failed: %v", err), http.StatusInternalServerError)
			return
		}

		LogAuditEvent(orgID, "CONNECTOR_SCAN", map[string]interface{}{
			"connector": "github",
			"owner":     req.Owner,
			"repo":      req.Repo,
			"assets":    len(assets),
			"edges":     len(edges),
		})

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"organization": orgID,
			"assets":       assets,
			"edges":        edges,
		})
	})


	// /v1/connectors/aws/accounts — register an AWS account for scanning
	http.HandleFunc("/v1/connectors/aws/accounts", func(w http.ResponseWriter, r *http.Request) {
		if !ValidateOnlyPOST(w, r) {
			return
		}
		ValidateBodySize(w, r, 10<<20)
		ar := AuthenticateRequest(r)
		if ar.Err != nil {
			Unauthorized(w)
			return
		}

		if featureChecker != nil {
			enabled, err := featureChecker.IsEnabled(r.Context(), ar.OrgID, "aws_connector")
			if err != nil {
				InternalError(w, "Internal server error during entitlement check")
				return
			}
			if !enabled {
				Forbidden(w, "Forbidden: Organization is not entitled to aws_connector")
				return
			}
		} else {
			// Fail closed: no entitlement infrastructure → no account registration.
			Forbidden(w, "Forbidden: Entitlement checks unavailable")
			return
		}

		var req struct {
			AccountID string `json:"accountId"`
			RoleARN   string `json:"roleArn"`
		}
		if err := ParseJSONBody(r, &req); err != nil {
			BadRequest(w, "Invalid request")
			return
		}

		if req.AccountID == "" || req.RoleARN == "" {
			BadRequest(w, "accountId and roleArn are required")
			return
		}

		// Validate the role ARN and extract the account ID.
		extractedAcct, err := aws.ValidateRoleARN(req.RoleARN)
		if err != nil {
			BadRequest(w, "roleArn format not allowed")
			return
		}
		if err := aws.ValidateAccountID(extractedAcct); err != nil {
			BadRequest(w, "roleArn format not allowed")
			return
		}

		// The account ID in the ARN must match the supplied accountId.
		if extractedAcct != req.AccountID {
			BadRequest(w, "accountId does not match roleArn")
			return
		}

		// Generate a server-side ExternalID so the caller never supplies it.
		externalID := "qb-" + generateUUID()

		store := entitlement.NewDBAWSAccountStore(db)
		account, err := store.Insert(r.Context(), ar.OrgID, req.AccountID, req.RoleARN, externalID)
		if err != nil {
			InternalError(w, "Failed to register AWS account")
			return
		}

		LogAuditEvent(ar.OrgID, "AWS_ACCOUNT_REGISTERED", map[string]interface{}{
			"accountId": account.AccountId,
			"roleArn":   account.RoleArn,
		})

		JSONResponse(w, http.StatusCreated, map[string]interface{}{
			"id":         account.Id,
			"accountId":  account.AccountId,
			"roleArn":    account.RoleArn,
			"externalId": account.ExternalId,
			"enabled":    account.Enabled,
		})
	})

	// /v1/connectors/aws/scan — account-scoped scan
	http.HandleFunc("/v1/connectors/aws/scan", func(w http.ResponseWriter, r *http.Request) {
		if !ValidateOnlyPOST(w, r) {
			return
		}
		ValidateBodySize(w, r, 10<<20)
		ar := AuthenticateRequest(r)
		if ar.Err != nil {
			Unauthorized(w)
			return
		}

		if featureChecker != nil {
			enabled, err := featureChecker.IsEnabled(r.Context(), ar.OrgID, "aws_connector")
			if err != nil {
				InternalError(w, "Internal server error during entitlement check")
				return
			}
			if !enabled {
				Forbidden(w, "Forbidden: Organization is not entitled to aws_connector")
				return
			}
		} else {
			Forbidden(w, "Forbidden: Entitlement checks unavailable")
			return
		}

		var req AWSScanRequest
		if err := ParseJSONBody(r, &req); err != nil {
			BadRequest(w, "Invalid request")
			return
		}

		if err := ValidateAWSScanRequest(req); err != nil {
			BadRequest(w, err.Error())
			return
		}

		// Validate the account ID format.
		if err := aws.ValidateAccountID(req.AccountID); err != nil {
			BadRequest(w, "accountId format not allowed")
			return
		}

		// Look up the registered account from the DB — never trust caller-supplied roleArn/externalId.
		store := entitlement.NewDBAWSAccountStore(db)
		account, err := store.GetForOrgAndAccount(r.Context(), ar.OrgID, req.AccountID)
		if err != nil {
			InternalError(w, "Failed to look up AWS account")
			return
		}
		if account == nil {
			Forbidden(w, "Forbidden: account not registered for this organization")
			return
		}

		// Validate requested regions.
		if err := aws.ValidateRegions(req.Regions, 5); err != nil {
			BadRequest(w, err.Error())
			return
		}

		cfg := aws.Config{
			Organization: ar.OrgID,
			RoleARN:      account.RoleArn,  // from DB, not caller
			ExternalID:   account.ExternalId, // from DB, not caller
			Regions:      req.Regions,
		}

		conn := aws.NewAWSConnector(cfg, featureChecker)
		assets, edges, err := conn.Discover(r.Context())
		if err != nil {
			InternalError(w, "Connector discovery failed")
			return
		}

		LogAuditEvent(ar.OrgID, "CONNECTOR_SCAN", map[string]interface{}{
			"connector":  "aws",
			"accountId":  account.AccountId,
			"roleArn":    account.RoleArn,
			"regions":    req.Regions,
			"assets":     len(assets),
			"edges":      len(edges),
		})

		JSONResponse(w, http.StatusOK, map[string]interface{}{
			"organization": ar.OrgID,
			"assets":       assets,
			"edges":        edges,
		})
	})

	fmt.Printf("Starting QuantumBlue Daemon on port %s...\n", port)
	return http.ListenAndServe(":"+port, nil)
}
