package cbom

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/psycho-prince/pqc-sdk/internal/policy"
	"github.com/xeipuuv/gojsonschema"
)

// Asset represents a discovered cryptographic asset.
type Asset struct {
	FilePath string    `json:"file_path"`
	Type     string    `json:"type"`
	Findings []Finding `json:"findings"`
}

// Finding represents a single cryptographic finding.
type Finding struct {
	Primitive     string `json:"primitive"`
	Location      string `json:"location"`
	Severity      string `json:"severity"`
	Type          string `json:"type"`
	QuantumStatus string `json:"quantum_status"`
}

// CBOM represents a standard Cryptographic Bill of Materials (CycloneDX 1.6 format).
type CBOM struct {
	BOMFormat   string      `json:"bomFormat"`
	SpecVersion string      `json:"specVersion"`
	Version     int         `json:"version"`
	Metadata    Metadata    `json:"metadata"`
	Components  []Component `json:"components"`
}

type Metadata struct {
	Timestamp string `json:"timestamp"`
}

type Component struct {
	Type             string            `json:"type"`
	BOMRef           string            `json:"bom-ref,omitempty"`
	Name             string            `json:"name"`
	Properties       []Property        `json:"properties,omitempty"`
	CryptoProperties *CryptoProperties `json:"cryptoProperties,omitempty"`
}

type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type CryptoProperties struct {
	AssetType           string               `json:"assetType"`
	AlgorithmProperties *AlgorithmProperties `json:"algorithmProperties,omitempty"`
}

type AlgorithmProperties struct {
	Primitive                string `json:"primitive,omitempty"`
	Curve                    string `json:"curve,omitempty"`
	KeyLength                int    `json:"keyLength,omitempty"`
	Padding                  string `json:"padding,omitempty"`
	NistQuantumSecurityLevel *int   `json:"nistQuantumSecurityLevel,omitempty"`
}

// NewCBOM creates a new, populated CBOM structure in CycloneDX 1.6 format.
func NewCBOM(assets []Asset) *CBOM {
	pol := policy.DefaultQuantumRiskPolicy()
	components := []Component{}
	for _, a := range assets {
		for _, f := range a.Findings {
			severity, qStatus := pol.GetRisk(f.Primitive)
			
			level := 1
			eval := "quantum-vulnerable"
			
			if qStatus == "compliant" || severity == "LOW" {
				level = 3
				eval = "fips-approved"
			} else if severity == "CRITICAL" || severity == "policy-violation" {
				level = 0
				eval = "not-approved"
			} else if severity == "HIGH" || severity == "quantum-vulnerable" {
				level = 1
				eval = "quantum-vulnerable"
			}

			assetType := "algorithm"
			pType := "unknown"
			primitiveLower := strings.ToLower(f.Primitive)
			
			if strings.Contains(primitiveLower, "tls") {
				assetType = "protocol"
			} else if strings.Contains(primitiveLower, "md5") || strings.Contains(primitiveLower, "sha") {
				pType = "hash"
			} else if strings.Contains(primitiveLower, "rsa") || strings.Contains(primitiveLower, "ecdsa") || strings.Contains(primitiveLower, "ed25519") {
				pType = "signature"
			} else if strings.Contains(primitiveLower, "des") || strings.Contains(primitiveLower, "aes") {
				pType = "block-cipher"
			} else if strings.Contains(primitiveLower, "ecdh") {
				pType = "key-agree"
			}

			var algoProps *AlgorithmProperties
			if assetType == "algorithm" {
				algoProps = &AlgorithmProperties{
					Primitive:                pType,
					NistQuantumSecurityLevel: &level,
				}
			}

			components = append(components, Component{
				Type:   "cryptographic-asset",
				BOMRef: fmt.Sprintf("%s-%s", f.Primitive, f.Location),
				Name:   f.Primitive,
				Properties: []Property{
					{Name: "nistQuantumEvaluation", Value: eval},
				},
				CryptoProperties: &CryptoProperties{
					AssetType:           assetType,
					AlgorithmProperties: algoProps,
				},
			})
		}
	}
	
	return &CBOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.6",
		Version:     1,
		Metadata: Metadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
		Components: components,
	}
}

// ToJSON serializes the CBOM to a JSON byte slice and validates it.
func (c *CBOM) ToJSON() ([]byte, error) {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return nil, err
	}

	if err := c.ValidateSchema(data); err != nil {
		return nil, fmt.Errorf("schema validation failed: %v", err)
	}

	return data, nil
}

// ValidateSchema performs a validation against CycloneDX 1.6 expectations.
func (c *CBOM) ValidateSchema(data []byte) error {
	pwd, _ := os.Getwd()
	schemaLoader := gojsonschema.NewReferenceLoader("file://" + pwd + "/schemas/cyclonedx-1.6-cbom.json")
	documentLoader := gojsonschema.NewBytesLoader(data)

	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		return fmt.Errorf("failed to load schema: %v", err)
	}

	if !result.Valid() {
		var errs []string
		for _, desc := range result.Errors() {
			errs = append(errs, desc.String())
		}
		return fmt.Errorf("invalid CBOM:\n%s", strings.Join(errs, "\n"))
	}

	return nil
}
