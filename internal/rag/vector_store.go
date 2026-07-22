package rag

import (
	"database/sql"
	_ "github.com/mattn/go-sqlite3"
)

// VectorStore manages local vector storage for PQC guidelines.
type VectorStore struct {
	db *sql.DB
}

// NewVectorStore initializes the SQLite database with vec extension support.
func NewVectorStore(dbPath string) (*VectorStore, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	// Enable vec extension (assuming it's loaded as a runtime extension)
	_, err = db.Exec("SELECT load_extension('vec0')")
	if err != nil {
		// If vec0 extension loading fails, we might need a fallback or better error handling
		// For now, continue to see if schema creation works
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS pqc_guidelines (
		id INTEGER PRIMARY KEY,
		content TEXT,
		embedding BLOB
	)`)
	
	return &VectorStore{db: db}, err
}

// Close closes the database connection.
func (v *VectorStore) Close() {
	v.db.Close()
}
