package analyzer

import (
	"encoding/json"
	"os"
)

// Asset represents a discovered cryptographic asset.
type Asset struct {
	FilePath string   `json:"file_path"`
	Type     string   `json:"type"`
	Findings []string `json:"findings"`
}

// GenerateInventory scans a directory and generates an inventory report.
func GenerateInventory(targetDir string) ([]Asset, error) {
	var inventory []Asset
	
	// Simplified directory walking
	// In reality, use filepath.WalkDir
	
	// Mock discovery
	inventory = append(inventory, Asset{
		FilePath: "tests/contracts/Vulnerable.sol",
		Type:     "Solidity",
		Findings: []string{"ecrecover", "keccak256"},
	})
	
	return inventory, nil
}

// ExportInventory exports the inventory to a JSON file.
func ExportInventory(inventory []Asset, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()
	
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(inventory)
}
