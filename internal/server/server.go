package server

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/psycho-prince/pqc-sdk/internal/crypto"
)

// StartServer initializes the HTTP daemon exposing PQC operations
func StartServer(port string) error {
	http.HandleFunc("/scan", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Scan triggered remotely\n")
	})

	// /v1/keys
	http.HandleFunc("/v1/keys", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		pkBytes, skBytes, err := crypto.GenerateIdentityKeyPair()
		if err != nil {
			http.Error(w, "Failed to generate keys", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"public_key":  pkBytes,
			"private_key": skBytes, // Note: In production this should be kept in HSM/KMS
		})
	})

	// /v1/sign
	http.HandleFunc("/v1/sign", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			Data       []byte `json:"data"`
			PrivateKey []byte `json:"private_key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		signature, err := crypto.SignEnvelope(req.Data, req.PrivateKey)
		if err != nil {
			http.Error(w, "Signing failed", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"signature": signature,
		})
	})

	// /v1/verify
	http.HandleFunc("/v1/verify", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
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

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"valid": valid,
		})
	})

	fmt.Printf("Starting QuantumBlue Daemon on port %s...\n", port)
	return http.ListenAndServe(":"+port, nil)
}
