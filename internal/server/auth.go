package server

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"

	_ "github.com/lib/pq"
)

var (
	db     *sql.DB
	dbOnce sync.Once
)

// InitDB connects to the unified PostgreSQL database
func InitDB(dsn string) error {
	var err error
	dbOnce.Do(func() {
		db, err = sql.Open("postgres", dsn)
		if err == nil {
			err = db.Ping()
		}
	})
	return err
}

// authenticate extracts the Bearer token, hashes it, and queries the ApiKey table
func authenticate(r *http.Request) (string, error) {
	if db == nil {
		return "", fmt.Errorf("database not initialized, authentication unavailable")
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("missing Authorization header")
	}

	var rawKey string
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return "", fmt.Errorf("invalid Authorization header format")
	}
	rawKey = strings.TrimPrefix(authHeader, "Bearer ")

	hash := sha256.New()
	hash.Write([]byte(rawKey))
	hashedKey := hex.EncodeToString(hash.Sum(nil))

	var orgID string
	query := `SELECT "organizationId" FROM "ApiKey" WHERE "keyHash" = $1 AND "revokedAt" IS NULL`
	err := db.QueryRow(query, hashedKey).Scan(&orgID)
	if err != nil {
		return "", fmt.Errorf("invalid or revoked API key")
	}

	return orgID, nil
}

// LogAuditEvent records a security-critical event directly to the database
func LogAuditEvent(orgID, action string, details map[string]interface{}) {
	detailsBytes, err := json.Marshal(details)
	if err != nil {
		return
	}

	if db == nil {
		fmt.Fprintf(os.Stderr, "[AUDIT FALLBACK] Action: %s, Org: %s, Details: %s\n", action, orgID, string(detailsBytes))
		return
	}

	query := `INSERT INTO "AuditEvent" ("id", "organizationId", "action", "details", "createdAt") VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)`
	_, err = db.Exec(query, generateUUID(), orgID, action, string(detailsBytes))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to log audit event: %v\n", err)
	}
}

func generateUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	// Set version 4 bits
	b[6] = (b[6] & 0x0f) | 0x40
	// Set variant bits
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}
