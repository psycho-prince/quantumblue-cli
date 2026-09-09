package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/psycho-prince/pqc-sdk/internal/crypto"
	"github.com/psycho-prince/pqc-sdk/internal/scanner"
)

// StartServer initializes the HTTP daemon exposing PQC operations
func StartServer(port, dsn string) error {
	if dsn != "" {
		if err := InitDB(dsn); err != nil {
			return fmt.Errorf("database initialization failed: %w", err)
		}
		fmt.Println("Connected to unified PostgreSQL database")
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
		
		// We can read public key to return it
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
			// Write to temp file
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

	fmt.Printf("Starting QuantumBlue Daemon on port %s...\n", port)
	return http.ListenAndServe(":"+port, nil)
}
