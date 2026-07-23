package cbom

import (
	"encoding/json"
	"time"
)

// CBOM represents a standard Cryptographic Bill of Materials.
type CBOM struct {
	Version   string    `json:"version"`
	Timestamp string    `json:"timestamp"`
	Assets    []Asset   `json:"assets"`
}

// Asset represents a discovered cryptographic asset.
type Asset struct {
	FilePath string   `json:"file_path"`
	Type     string   `json:"type"`
	Findings []Finding `json:"findings"`
}

// Finding represents a single cryptographic finding.
type Finding struct {
	Primitive string `json:"primitive"`
	Location  string `json:"location"`
	Severity  string `json:"severity"`
	Type      string `json:"type"`
}

// NewCBOM creates a new, populated CBOM structure.
func NewCBOM(assets []Asset) *CBOM {
	return &CBOM{
		Version:   "1.0.0",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Assets:    assets,
	}
}

// ToJSON serializes the CBOM to a JSON byte slice.
func (c *CBOM) ToJSON() ([]byte, error) {
	return json.MarshalIndent(c, "", "  ")
}
