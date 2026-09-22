package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/psycho-prince/pqc-sdk/internal/crypto"
)

// EvidenceStatus tracks the lifecycle of an evidence item.
type EvidenceStatus string

const (
	StatusAcquired  EvidenceStatus = "ACQUIRED"
	StatusHashed    EvidenceStatus = "HASHED"
	StatusVerified  EvidenceStatus = "VERIFIED"
	StatusTampered  EvidenceStatus = "INTEGRITY_FAILURE"
	StatusArchived  EvidenceStatus = "ARCHIVED"
)

// Evidence represents a piece of electronic evidence under management.
type Evidence struct {
	ID              string           `json:"evidence_id"`
	CaseID          string           `json:"case_id,omitempty"`
	OriginalName    string           `json:"original_name"`
	MimeType        string           `json:"mime_type,omitempty"`
	SizeBytes       int64            `json:"size_bytes"`
	SHA256          string           `json:"sha256"`
	Status          EvidenceStatus   `json:"status"`
	AcquiredAt      time.Time        `json:"acquired_at"`
	AcquiredBy      string           `json:"acquired_by"`
	DeviceMake      string           `json:"device_make,omitempty"`
	DeviceModel     string           `json:"device_model,omitempty"`
	DeviceSerial    string           `json:"device_serial,omitempty"`
	DeviceIMEI      string           `json:"device_imei,omitempty"`
	DeviceUID       string           `json:"device_uid,omitempty"`
	DeviceMAC       string           `json:"device_mac,omitempty"`
	CloudID         string           `json:"cloud_id,omitempty"`
	OSVersion       string           `json:"os_version,omitempty"`
	BIOSVersion     string           `json:"bios_version,omitempty"`
	FirmwareVersion string           `json:"firmware_version,omitempty"`
	Source          string           `json:"source"`
	SourceURL       string           `json:"source_url,omitempty"`
	SourceIP        string           `json:"source_ip,omitempty"`
	AcquisitionPath string           `json:"acquisition_path"`
	OriginalHash    string           `json:"original_hash"`
	CurrentHash     string           `json:"current_hash,omitempty"`
	IntegrityCheck  *IntegrityResult `json:"integrity_check,omitempty"`
	Manifest        json.RawMessage  `json:"manifest,omitempty"`
	CreatedAt       time.Time        `json:"created_at"`
	UpdatedAt       time.Time        `json:"updated_at"`
}

// IntegrityResult is the result of comparing current hash against original.
type IntegrityResult struct {
	OriginalHash string    `json:"original_hash"`
	CurrentHash  string    `json:"current_hash"`
	Match        bool      `json:"match"`
	Tampered     bool      `json:"tampered"`
	CheckedAt    time.Time `json:"checked_at"`
}

// AcquisitionManifest is the full metadata captured at evidence acquisition time.
type AcquisitionManifest struct {
	EvidenceID      string    `json:"evidence_id"`
	OriginalName    string    `json:"original_name"`
	MimeType        string    `json:"mime_type"`
	SizeBytes       int64     `json:"size_bytes"`
	SHA256          string    `json:"sha256"`
	AcquiredAt      time.Time `json:"acquired_at"`
	AcquiredBy      string    `json:"acquired_by"`
	Source          string    `json:"source"`
	SourceURL       string    `json:"source_url,omitempty"`
	SourceIP        string    `json:"source_ip,omitempty"`
	AcquisitionPath string    `json:"acquisition_path"`
	DeviceMake      string    `json:"device_make,omitempty"`
	DeviceModel     string    `json:"device_model,omitempty"`
	DeviceSerial    string    `json:"device_serial,omitempty"`
	DeviceIMEI      string    `json:"device_imei,omitempty"`
	DeviceUID       string    `json:"device_uid,omitempty"`
	DeviceMAC       string    `json:"device_mac,omitempty"`
	CloudID         string    `json:"cloud_id,omitempty"`
	OSVersion       string    `json:"os_version,omitempty"`
	BIOSVersion     string    `json:"bios_version,omitempty"`
	FirmwareVersion string    `json:"firmware_version,omitempty"`
	CaseID          string    `json:"case_id,omitempty"`
	Environment     string    `json:"environment"`
	LawReference    string    `json:"law_reference"`
}

// Engine manages evidence acquisition, hashing, integrity checking, and manifest generation.
type Engine struct {
	keyProvider crypto.KeyProvider
}

// NewEngine creates an evidence engine.
func NewEngine(kp crypto.KeyProvider) *Engine {
	if kp == nil {
		kp = crypto.NewFileKeyProvider(".")
	}
	return &Engine{keyProvider: kp}
}

// Acquire creates a new evidence record from raw file data.
func (e *Engine) Acquire(data []byte, req AcquisitionRequest) (*Evidence, error) {
	hash := sha256.Sum256(data)
	hashStr := hex.EncodeToString(hash[:])
	now := time.Now()

	evidence := &Evidence{
		ID:              fmt.Sprintf("QB-EVD-%06d", nextEvidenceCounter()),
		OriginalName:    req.OriginalName,
		MimeType:        req.MimeType,
		SizeBytes:       int64(len(data)),
		SHA256:          hashStr,
		Status:          StatusAcquired,
		AcquiredAt:      now,
		AcquiredBy:      req.AcquiredBy,
		DeviceMake:      req.DeviceMake,
		DeviceModel:     req.DeviceModel,
		DeviceSerial:    req.DeviceSerial,
		DeviceIMEI:      req.DeviceIMEI,
		DeviceUID:       req.DeviceUID,
		DeviceMAC:       req.DeviceMAC,
		CloudID:         req.CloudID,
		OSVersion:       req.OSVersion,
		BIOSVersion:     req.BIOSVersion,
		FirmwareVersion: req.FirmwareVersion,
		Source:          req.Source,
		SourceURL:       req.SourceURL,
		SourceIP:        req.SourceIP,
		AcquisitionPath: req.AcquisitionPath,
		OriginalHash:    hashStr,
		CurrentHash:     hashStr,
		CaseID:          req.CaseID,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	manifest := AcquisitionManifest{
		EvidenceID:      evidence.ID,
		OriginalName:    evidence.OriginalName,
		MimeType:        evidence.MimeType,
		SizeBytes:       evidence.SizeBytes,
		SHA256:          evidence.SHA256,
		AcquiredAt:      evidence.AcquiredAt,
		AcquiredBy:      evidence.AcquiredBy,
		Source:          evidence.Source,
		SourceURL:       evidence.SourceURL,
		SourceIP:        evidence.SourceIP,
		AcquisitionPath: evidence.AcquisitionPath,
		DeviceMake:      evidence.DeviceMake,
		DeviceModel:     evidence.DeviceModel,
		DeviceSerial:    evidence.DeviceSerial,
		DeviceIMEI:      evidence.DeviceIMEI,
		DeviceUID:       evidence.DeviceUID,
		DeviceMAC:       evidence.DeviceMAC,
		CloudID:         evidence.CloudID,
		OSVersion:       evidence.OSVersion,
		BIOSVersion:     evidence.BIOSVersion,
		FirmwareVersion: evidence.FirmwareVersion,
		CaseID:          evidence.CaseID,
		Environment:     req.Environment,
		LawReference:    req.LawReference,
	}
	manifestData, _ := json.Marshal(manifest)
	evidence.Manifest = manifestData

	return evidence, nil
}

// CheckIntegrity compares the current hash of the evidence data against the original hash.
func (e *Engine) CheckIntegrity(evidence *Evidence, currentData []byte) *IntegrityResult {
	currentHash := sha256.Sum256(currentData)
	currentHashStr := hex.EncodeToString(currentHash[:])

	result := &IntegrityResult{
		OriginalHash: evidence.OriginalHash,
		CurrentHash:  currentHashStr,
		Match:        currentHashStr == evidence.OriginalHash,
		Tampered:     currentHashStr != evidence.OriginalHash,
		CheckedAt:    time.Now(),
	}

	if result.Tampered {
		evidence.Status = StatusTampered
	} else {
		evidence.Status = StatusVerified
	}
	evidence.CurrentHash = currentHashStr
	evidence.IntegrityCheck = result
	evidence.UpdatedAt = time.Now()

	return result
}

// AcquisitionRequest is the input for evidence acquisition.
type AcquisitionRequest struct {
	OriginalName    string
	MimeType        string
	AcquiredBy      string
	DeviceMake      string
	DeviceModel     string
	DeviceSerial    string
	DeviceIMEI      string
	DeviceUID       string
	DeviceMAC       string
	CloudID         string
	OSVersion       string
	BIOSVersion     string
	FirmwareVersion string
	Source          string
	SourceURL       string
	SourceIP        string
	AcquisitionPath string
	CaseID          string
	Environment     string
	LawReference    string
}

// Hasher provides hash computation.
type Hasher struct{}

// HashSHA256 computes SHA-256 of data and returns hex string.
func (h *Hasher) HashSHA256(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

var evidenceCounter uint64

func nextEvidenceCounter() uint64 {
	evidenceCounter++
	return evidenceCounter
}
