package analyzer

import (
	"os"
	"path/filepath"
	"sort"
	"github.com/psycho-prince/pqc-sdk/internal/scanner"
	"github.com/psycho-prince/pqc-sdk/internal/cbom"
	"github.com/psycho-prince/pqc-sdk/internal/policy"
)

// PrioritizeAssets sorts assets by their highest severity finding.
func PrioritizeAssets(assets []cbom.Asset) []cbom.Asset {
	severityMap := map[string]int{
		policy.SeverityCritical: 3,
		policy.SeverityHigh:     2,
		policy.SeverityMedium:   1,
		policy.SeverityLow:      0,
	}

	sort.Slice(assets, func(i, j int) bool {
		maxI := 0
		for _, f := range assets[i].Findings {
			if severityMap[f.Severity] > maxI {
				maxI = severityMap[f.Severity]
			}
		}
		maxJ := 0
		for _, f := range assets[j].Findings {
			if severityMap[f.Severity] > maxJ {
				maxJ = severityMap[f.Severity]
			}
		}
		return maxI > maxJ
	})
	return assets
}

// GenerateInventory scans a directory and returns a slice of CBOM assets.
func GenerateInventory(targetDir string) ([]cbom.Asset, error) {
	var assets []cbom.Asset
	goScanner := scanner.NewGoScanner()
	binScanner := scanner.NewBinaryScanner()
	confScanner := scanner.NewConfigScanner()

	err := filepath.WalkDir(targetDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		
		var findings []scanner.CBOMItem
		var fileType string

		if !d.IsDir() {
			ext := filepath.Ext(d.Name())
			if ext == ".go" {
				findings, err = goScanner.Scan(path)
				fileType = "Go"
			} else if ext == "" || ext == ".bin" || ext == ".so" {
				findings, err = binScanner.Scan(path)
				fileType = "Binary"
			} else {
				findings, err = confScanner.Scan(path)
				fileType = "Config"
			}

			if err == nil && len(findings) > 0 {
				var cbomFindings []cbom.Finding
				for _, f := range findings {
					cbomFindings = append(cbomFindings, cbom.Finding{
						Primitive: f.Primitive,
						Location:  f.Location,
						Severity:  f.Severity,
						Type:      f.Type,
					})
				}
				assets = append(assets, cbom.Asset{
					FilePath: path,
					Type:     fileType,
					Findings: cbomFindings,
				})
			}
		}
		return nil
	})
	
	return assets, err
}

// ExportInventory exports the inventory to a JSON file in CBOM format.
func ExportInventory(assets []cbom.Asset, outputPath string) error {
	prioritized := PrioritizeAssets(assets)
	cbomData := cbom.NewCBOM(prioritized)
	jsonData, err := cbomData.ToJSON()
	if err != nil {
		return err
	}
	
	return os.WriteFile(outputPath, jsonData, 0644)
}
