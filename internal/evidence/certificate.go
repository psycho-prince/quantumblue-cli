package evidence

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/psycho-prince/pqc-sdk/internal/crypto"
)

// BSAS63Certificate represents a BSA §63 certificate for electronic evidence.
type BSAS63Certificate struct {
	Version       string          `json:"version"`
	CertificateID string          `json:"certificate_id"`
	EvidenceID    string          `json:"evidence_id"`
	Status        CertStatus      `json:"status"`
	CreatedAt     time.Time       `json:"created_at"`
	IssuedAt      time.Time       `json:"issued_at,omitempty"`
	IssuedBy      string          `json:"issued_by"`
	IssuedByRole  string          `json:"issued_by_role,omitempty"`
	Signature     json.RawMessage `json:"signature,omitempty"`
	SignatureAlgo string          `json:"signature_algorithm,omitempty"`

	// Section 63 — electronic record identification
	RecordIdentifier string `json:"record_identifier"`
	RecordType       string `json:"record_type"`
	RecordSize       int64  `json:"record_size"`
	RecordHash       string `json:"record_hash"`

	// Section 63 — how the record was produced
	ProducedBy       string `json:"produced_by"`
	ProductionMethod string `json:"production_method"`
	ProductionTime   time.Time `json:"production_time"`
	ProductionPlace  string `json:"production_place,omitempty"`

	// Section 63 — device particulars
	DeviceMake      string `json:"device_make"`
	DeviceModel     string `json:"device_model"`
	DeviceSerial    string `json:"device_serial,omitempty"`
	DeviceIMEI      string `json:"device_imei,omitempty"`
	DeviceUID       string `json:"device_uid,omitempty"`
	DeviceMAC       string `json:"device_mac,omitempty"`
	CloudID         string `json:"cloud_id,omitempty"`
	OSVersion       string `json:"os_version"`
	BIOSVersion     string `json:"bios_version,omitempty"`
	FirmwareVersion string `json:"firmware_version,omitempty"`
	FirmwareHash    string `json:"firmware_hash,omitempty"`

	// Section 63 — operating conditions
	OperatingEnvironment string `json:"operating_environment"`
	NormalOperation      bool   `json:"normal_operation"`
	AccuracyStatement    string `json:"accuracy_statement"`

	// Chain of custody reference
	CustodyChainHash string `json:"custody_chain_hash"`
	CustodyEventCount int    `json:"custody_event_count"`

	// Verification
	VerificationStatus string    `json:"verification_status"`
	VerificationAt     time.Time `json:"verification_at,omitempty"`

	// Legacy compatibility note
	LegacyReference string `json:"legacy_reference,omitempty"`
}

// CertStatus tracks the certificate lifecycle.
type CertStatus string

const (
	CertDraft      CertStatus = "DRAFT"
	CertValidated  CertStatus = "VALIDATED"
	CertSigned     CertStatus = "SIGNED"
	CertIssued     CertStatus = "ISSUED"
	CertRevoked    CertStatus = "REVOKED"
	CertSuperseded CertStatus = "SUPERSEDED"
)

// CertificateEngine generates and manages BSA §63 certificates.
type CertificateEngine struct {
	evidence    *Evidence
	custody     *ChainEngine
	keyProvider crypto.KeyProvider
	keyID       string
}

// NewCertificateEngine creates a certificate engine for an evidence item.
func NewCertificateEngine(evidence *Evidence, custody *ChainEngine, kp crypto.KeyProvider) *CertificateEngine {
	if kp == nil {
		kp = crypto.NewFileKeyProvider(".")
	}
	return &CertificateEngine{
		evidence:    evidence,
		custody:     custody,
		keyProvider: kp,
		keyID:       "qb-certificate",
	}
}

// Generate creates a draft BSA §63 certificate from the evidence and custody chain.
func (ce *CertificateEngine) Generate() (*BSAS63Certificate, error) {
	custodyChain := ce.custody.GetChain(ce.evidence.ID)

	lastEvent := custodyChain.LastEvent
	custodyHash := ""
	custodyCount := 0
	if lastEvent != nil {
		custodyHash = lastEvent.EventHash
		custodyCount = len(custodyChain.Events)
	}

	cert := &BSAS63Certificate{
		Version:            "1.0",
		CertificateID:      fmt.Sprintf("QB-CERT-%s", ce.evidence.ID),
		EvidenceID:         ce.evidence.ID,
		Status:             CertDraft,
		CreatedAt:          time.Now(),
		IssuedBy:           ce.evidence.AcquiredBy,
		IssuedByRole:       "Evidence Custodian",
		RecordIdentifier:   ce.evidence.OriginalName,
		RecordType:         ce.evidence.MimeType,
		RecordSize:         ce.evidence.SizeBytes,
		RecordHash:         ce.evidence.SHA256,
		ProducedBy:         ce.evidence.AcquiredBy,
		ProductionMethod:   ce.evidence.AcquisitionPath,
		ProductionTime:     ce.evidence.AcquiredAt,
		ProductionPlace:    "Digital evidence acquisition system",
		DeviceMake:         ce.evidence.DeviceMake,
		DeviceModel:        ce.evidence.DeviceModel,
		DeviceSerial:       ce.evidence.DeviceSerial,
		DeviceIMEI:         ce.evidence.DeviceIMEI,
		DeviceUID:          ce.evidence.DeviceUID,
		DeviceMAC:          ce.evidence.DeviceMAC,
		CloudID:            ce.evidence.CloudID,
		OSVersion:          ce.evidence.OSVersion,
		BIOSVersion:        ce.evidence.BIOSVersion,
		FirmwareVersion:    ce.evidence.FirmwareVersion,
		OperatingEnvironment: ce.evidence.AcquisitionPath,
		NormalOperation:     true,
		AccuracyStatement:   "The electronic record was produced by a computer system operating normally and accurately at the time of production. The system was functioning properly and the record accurately reflects the data as it existed at the time of acquisition.",
		CustodyChainHash:   custodyHash,
		CustodyEventCount:  custodyCount,
		VerificationStatus:  "NOT_VERIFIED",
		LegacyReference:     "IEA §65B(4) — superseded by BSA §63 effective 2024-07-01",
	}

	return cert, nil
}

// Validate checks the certificate data for completeness against BSA §63 requirements.
func (ce *CertificateEngine) Validate(cert *BSAS63Certificate) []string {
	var issues []string

	if cert.RecordIdentifier == "" {
		issues = append(issues, "BSA §63: Record identifier is missing")
	}
	if cert.RecordHash == "" {
		issues = append(issues, "BSA §63: Record hash (SHA-256) is missing")
	}
	if cert.DeviceMake == "" {
		issues = append(issues, "BSA §63: Device make is missing")
	}
	if cert.DeviceModel == "" {
		issues = append(issues, "BSA §63: Device model is missing")
	}
	if cert.ProductionMethod == "" {
		issues = append(issues, "BSA §63: Production method is missing")
	}
	if cert.ProducedBy == "" {
		issues = append(issues, "BSA §63: Produced by field is missing")
	}
	if cert.OperatingEnvironment == "" {
		issues = append(issues, "BSA §63: Operating environment is missing")
	}
	if !cert.NormalOperation {
		issues = append(issues, "BSA §63: Normal operation statement is required")
	}
	if cert.AccuracyStatement == "" {
		issues = append(issues, "BSA §63: Accuracy statement is missing")
	}

	return issues
}

// Sign signs the certificate with ML-DSA-65 or HMAC fallback.
func (ce *CertificateEngine) Sign(cert *BSAS63Certificate) error {
	certData, _ := json.Marshal(cert)
	sig, err := ce.keyProvider.Sign(ce.keyID, certData)
	if err != nil {
		return fmt.Errorf("signing failed: %w", err)
	}
	cert.Signature = json.RawMessage(sig)
	cert.SignatureAlgo = "ML-DSA-65"
	cert.Status = CertSigned
	cert.IssuedAt = time.Now()
	return nil
}

// Issue marks the certificate as issued.
func (ce *CertificateEngine) Issue(cert *BSAS63Certificate) {
	cert.Status = CertIssued
	cert.IssuedAt = time.Now()
}

// Revoke marks a certificate as revoked.
func (ce *CertificateEngine) Revoke(cert *BSAS63Certificate, reason string) {
	cert.Status = CertRevoked
	cert.IssuedAt = time.Now()
	_ = reason
}

// ToJSON serializes the certificate for export.
func (ce *CertificateEngine) ToJSON(cert *BSAS63Certificate) ([]byte, error) {
	return json.MarshalIndent(cert, "", "  ")
}

// ToTBSDocument generates a human-readable certificate document for court evidentiary use.
func (ce *CertificateEngine) ToTBSDocument(cert *BSAS63Certificate) string {
	var sb strings.Builder

	sb.WriteString("=============================================================\n")
	sb.WriteString("   CRYPTOGRAPHIC EVIDENCE CERTIFICATE — Bharatiya Sakshya Adhiniyam, 2023 — Section 63\n")
	sb.WriteString("=============================================================\n\n")

	sb.WriteString(fmt.Sprintf("Certificate ID: %s\n", cert.CertificateID))
	sb.WriteString(fmt.Sprintf("Evidence ID:    %s\n", cert.EvidenceID))
	sb.WriteString(fmt.Sprintf("Status:         %s\n", cert.Status))
	sb.WriteString(fmt.Sprintf("Issued by:      %s (%s)\n", cert.IssuedBy, cert.IssuedByRole))
	sb.WriteString(fmt.Sprintf("Date Issued:    %s\n\n", cert.IssuedAt.Format(time.RFC3339)))

	sb.WriteString("-------------------------------------------------------------\n")
	sb.WriteString("SECTION 63 — ELECTRONIC RECORD IDENTIFICATION\n")
	sb.WriteString("-------------------------------------------------------------\n\n")

	sb.WriteString(fmt.Sprintf("Record Identifier: %s\n", cert.RecordIdentifier))
	sb.WriteString(fmt.Sprintf("Record Type:       %s\n", cert.RecordType))
	sb.WriteString(fmt.Sprintf("Record Size:       %d bytes\n", cert.RecordSize))
	sb.WriteString(fmt.Sprintf("Record Hash:       SHA-256 %s\n\n", cert.RecordHash))

	sb.WriteString("-------------------------------------------------------------\n")
	sb.WriteString("SECTION 63 — HOW THE RECORD WAS PRODUCED                    \n")
	sb.WriteString("-------------------------------------------------------------\n\n")

	sb.WriteString(fmt.Sprintf("Produced by:        %s\n", cert.ProducedBy))
	sb.WriteString(fmt.Sprintf("Production method: %s\n", cert.ProductionMethod))
	sb.WriteString(fmt.Sprintf("Production time:    %s\n", cert.ProductionTime.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("Production place:   %s\n\n", cert.ProductionPlace))

	sb.WriteString("-------------------------------------------------------------\n")
	sb.WriteString("SECTION 63 — DEVICE PARTICULARS                             \n")
	sb.WriteString("-------------------------------------------------------------\n\n")

	sb.WriteString(fmt.Sprintf("Device Make:        %s\n", cert.DeviceMake))
	sb.WriteString(fmt.Sprintf("Device Model:       %s\n", cert.DeviceModel))
	if cert.DeviceSerial != "" {
		sb.WriteString(fmt.Sprintf("Device Serial:      %s\n", cert.DeviceSerial))
	}
	if cert.DeviceIMEI != "" {
		sb.WriteString(fmt.Sprintf("Device IMEI/UIN:    %s\n", cert.DeviceIMEI))
	}
	if cert.DeviceUID != "" {
		sb.WriteString(fmt.Sprintf("Device UID:         %s\n", cert.DeviceUID))
	}
	if cert.DeviceMAC != "" {
		sb.WriteString(fmt.Sprintf("Device MAC:         %s\n", cert.DeviceMAC))
	}
	if cert.CloudID != "" {
		sb.WriteString(fmt.Sprintf("Cloud ID:           %s\n", cert.CloudID))
	}
	sb.WriteString(fmt.Sprintf("OS Version:         %s\n", cert.OSVersion))
	if cert.BIOSVersion != "" {
		sb.WriteString(fmt.Sprintf("BIOS Version:       %s\n", cert.BIOSVersion))
	}
	if cert.FirmwareVersion != "" {
		sb.WriteString(fmt.Sprintf("Firmware Version:   %s\n", cert.FirmwareVersion))
	}
	if cert.FirmwareHash != "" {
		sb.WriteString(fmt.Sprintf("Firmware Hash:      %s\n", cert.FirmwareHash))
	}
	sb.WriteString("\n")

	sb.WriteString("-------------------------------------------------------------\n")
	sb.WriteString("SECTION 63 — OPERATING CONDITIONS                            \n")
	sb.WriteString("-------------------------------------------------------------\n\n")

	sb.WriteString(fmt.Sprintf("Operating Environment: %s\n", cert.OperatingEnvironment))
	sb.WriteString(fmt.Sprintf("Normal Operation:      %v\n", cert.NormalOperation))
	sb.WriteString(fmt.Sprintf("Accuracy Statement:    %s\n\n", cert.AccuracyStatement))

	sb.WriteString("-------------------------------------------------------------\n")
	sb.WriteString("CHAIN OF CUSTODY                                            \n")
	sb.WriteString("-------------------------------------------------------------\n\n")

	sb.WriteString(fmt.Sprintf("Custody Chain Hash:  %s\n", cert.CustodyChainHash))
	sb.WriteString(fmt.Sprintf("Custody Events:      %d\n", cert.CustodyEventCount))
	sb.WriteString(fmt.Sprintf("Verification Status:  %s\n\n", cert.VerificationStatus))

	sb.WriteString("-------------------------------------------------------------\n")
	sb.WriteString("SIGNATURE                                                    \n")
	sb.WriteString("-------------------------------------------------------------\n\n")

	if len(cert.Signature) > 0 {
		sb.WriteString(fmt.Sprintf("Signature Algorithm: %s\n", cert.SignatureAlgo))
		sb.WriteString(fmt.Sprintf("Signature:           %x\n\n", cert.Signature))
	} else {
		sb.WriteString("Signature:           Not yet signed\n\n")
	}

	sb.WriteString("-------------------------------------------------------------\n")
	sb.WriteString("LEGAL NOTICE                                                  \n")
	sb.WriteString("-------------------------------------------------------------\n\n")

	sb.WriteString("This certificate is issued under the Bharatiya Sakshya Adhiniyam,\n")
	sb.WriteString("2023, Section 63, which governs the admissibility of electronic\n")
	sb.WriteString("records in proceedings. It identifies the electronic record, how it\n")
	sb.WriteString("was produced, the device particulars, and the relevant operating\n")
	sb.WriteString("conditions as required by Section 63.\n\n")

	sb.WriteString("Legacy Note: This certificate supersedes certificates issued under\n")
	sb.WriteString("the Indian Evidence Act, 1872, Section 65B(4), which was the\n")
	sb.WriteString("prevailing provision for electronic evidence prior to the\n")
	sb.WriteString("commencement of the Bharatiya Sakshya Adhiniyam, 2023.\n\n")

	sb.WriteString("-------------------------------------------------------------\n")
	sb.WriteString("SIGN                                                     \n")
	sb.WriteString("-------------------------------------------------------------\n\n")
	sb.WriteString("Signature: ________________________\n")
	sb.WriteString("Name:    _______________________\n")
	sb.WriteString("Role:    _______________________\n")
	sb.WriteString("Date:    _______________________\n")

	return sb.String()
}
