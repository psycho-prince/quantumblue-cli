package server

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	_ "github.com/lib/pq"
)

var db *sql.DB

// InitDB connects to the unified PostgreSQL database
func InitDB(dsn string) error {
	var err error
	db, err = sql.Open("postgres", dsn)
	if err != nil {
		return fmt.Errorf("failed to connect to db: %w", err)
	}
	return db.Ping()
}

// authenticate extracts the Bearer token, hashes it, and queries Prisma's ApiKey table
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

// LogAuditEvent records a security-critical event directly to Postgres
func LogAuditEvent(orgID, action string, details map[string]interface{}) {
	if db == nil {
		// If DB isn't initialized, skip
		return
	}
	
	detailsBytes, err := json.Marshal(details)
	if err != nil {
		return
	}

	query := `INSERT INTO "AuditEvent" ("id", "organizationId", "action", "details", "createdAt") VALUES (gen_random_uuid(), $1, $2, $3, NOW())`
	_, err = db.Exec(query, orgID, action, string(detailsBytes))
	if err != nil {
		fmt.Printf("Failed to log audit event: %v\n", err)
	}
}
