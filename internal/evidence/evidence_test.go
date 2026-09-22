package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/psycho-prince/pqc-sdk/internal/crypto"
)

func TestEvidence_Acquire(t *testing.T) {
	engine := NewEngine(nil)

	data := []byte("test evidence content")
	req := AcquisitionRequest{
		OriginalName:    "evidence.pdf",
		MimeType:        "application/pdf",
		AcquiredBy:      "investigator-1",
		DeviceMake:      "Apple",
		DeviceModel:     "MacBook Pro",
		DeviceSerial:    "C02XYZ1234",
		OSVersion:       "macOS 14.5",
		Source:          "manual-upload",
		AcquisitionPath: "web-upload",
		CaseID:          "CASE-2026-001",
		Environment:     "investigation",
		LawReference:    "BSA s63",
	}

	ev, err := engine.Acquire(data, req)
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}

	if ev.ID == "" {
		t.Error("evidence ID is empty")
	}
	if ev.OriginalName != "evidence.pdf" {
		t.Errorf("original name: got %q, want %q", ev.OriginalName, "evidence.pdf")
	}
	if ev.Status != StatusAcquired {
		t.Errorf("status: got %q, want %q", ev.Status, StatusAcquired)
	}
	if ev.AcquiredBy != "investigator-1" {
		t.Errorf("acquired_by: got %q, want %q", ev.AcquiredBy, "investigator-1")
	}
	if ev.DeviceMake != "Apple" {
		t.Errorf("device_make: got %q, want %q", ev.DeviceMake, "Apple")
	}
	if ev.CaseID != "CASE-2026-001" {
		t.Errorf("case_id: got %q, want %q", ev.CaseID, "CASE-2026-001")
	}

	expectedHash := sha256.Sum256(data)
	expectedHex := hex.EncodeToString(expectedHash[:])
	if ev.SHA256 != expectedHex {
		t.Errorf("SHA-256 mismatch: got %s, want %s", ev.SHA256, expectedHex)
	}
	if ev.OriginalHash != expectedHex {
		t.Error("original hash not set correctly")
	}

	if ev.Manifest == nil || len(ev.Manifest) == 0 {
		t.Error("manifest is empty")
	}
}

func TestEvidence_CheckIntegrity(t *testing.T) {
	engine := NewEngine(nil)

	originalData := []byte("electronic evidence")
	ev, err := engine.Acquire(originalData, AcquisitionRequest{
		OriginalName: "document.txt",
		Source:       "upload",
		AcquiredBy:   "user-1",
	})
	if err != nil {
		t.Fatal(err)
	}

	result := engine.CheckIntegrity(ev, originalData)
	if !result.Match {
		t.Error("expected integrity match for identical data")
	}
	if result.Tampered {
		t.Error("should not be flagged as tampered")
	}
	if ev.Status != StatusVerified {
		t.Errorf("status should be VERIFIED, got %q", ev.Status)
	}

	tamperedData := []byte("electronic evidence MODIFIED")
	result2 := engine.CheckIntegrity(ev, tamperedData)
	if result2.Match {
		t.Error("expected integrity failure for modified data")
	}
	if !result2.Tampered {
		t.Error("should be flagged as tampered")
	}
	if ev.Status != StatusTampered {
		t.Errorf("status should be INTEGRITY_FAILURE, got %q", ev.Status)
	}
}

func TestCustodyChain_BasicFlow(t *testing.T) {
	kp := crypto.NewFileKeyProvider(".")
	ce := NewChainEngine(kp, "test-evidence")

	event1, err := ce.LogEvent(CustodyEventRequest{
		EvidenceID: "QB-EVD-000001",
		Actor:      "investigator-1",
		Action:     "ACQUIRED",
		Details:    map[string]interface{}{"file": "evidence.pdf"},
	})
	if err != nil {
		t.Fatalf("LogEvent ACQUIRED failed: %v", err)
	}
	if event1.Action != "ACQUIRED" {
		t.Errorf("action: got %q, want ACQUIRED", event1.Action)
	}
	if event1.PreviousHash != "" {
		t.Error("first event should have empty previous hash")
	}
	if event1.EventHash == "" {
		t.Error("event hash should be set")
	}

	event2, err := ce.LogEvent(CustodyEventRequest{
		EvidenceID: "QB-EVD-000001",
		Actor:      "investigator-1",
		Action:     "HASHED",
		Details:    map[string]interface{}{"algorithm": "SHA-256"},
	})
	if err != nil {
		t.Fatalf("LogEvent HASHED failed: %v", err)
	}
	if event2.PreviousHash != event1.EventHash {
		t.Errorf("previous hash mismatch: got %s, want %s", event2.PreviousHash, event1.EventHash)
	}

	chain, err := ce.VerifyChain("QB-EVD-000001")
	if err != nil {
		t.Fatalf("VerifyChain failed: %v", err)
	}
	if !chain.Verified {
		t.Error("chain should be verified")
	}
	if len(chain.Events) != 2 {
		t.Errorf("expected 2 events, got %d", len(chain.Events))
	}
}

func TestCustodyChain_TamperDetection(t *testing.T) {
	kp := crypto.NewFileKeyProvider(".")
	ce := NewChainEngine(kp, "test-evidence")

	ce.LogEvent(CustodyEventRequest{
		EvidenceID: "QB-EVD-TAMPER",
		Actor:      "user-1",
		Action:     "ACQUIRED",
		Details:    map[string]interface{}{"test": true},
	})

	events := ce.events["QB-EVD-TAMPER"]
	if len(events) > 0 {
		events[0].EventHash = "tampered-hash"
		ce.events["QB-EVD-TAMPER"] = events
	}

	_, err := ce.VerifyChain("QB-EVD-TAMPER")
	if err == nil {
		t.Error("expected error for tampered chain")
	}
}

func TestCertificateEngine_Generate(t *testing.T) {
	kp := crypto.NewFileKeyProvider(".")
	ce := NewChainEngine(kp, "test")
	ev := &Evidence{
		ID:              "QB-EVD-000001",
		OriginalName:    "evidence.pdf",
		MimeType:        "application/pdf",
		SizeBytes:       4096,
		SHA256:          "abc123def456",
		AcquiredBy:      "investigator-1",
		AcquiredAt:      time.Now(),
		DeviceMake:      "Apple",
		DeviceModel:     "MacBook Pro",
		AcquisitionPath: "web-upload",
		OriginalHash:    "abc123def456",
		OSVersion:       "macOS 14.5",
	}
	certEng := NewCertificateEngine(ev, ce, kp)

	cert, err := certEng.Generate()
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if cert.CertificateID == "" {
		t.Error("certificate ID is empty")
	}
	if cert.Status != CertDraft {
		t.Errorf("status: got %q, want DRAFT", cert.Status)
	}
	if cert.RecordIdentifier != "evidence.pdf" {
		t.Errorf("record_identifier: got %q, want %q", cert.RecordIdentifier, "evidence.pdf")
	}
	if cert.RecordHash != "abc123def456" {
		t.Errorf("record_hash: got %q, want %q", cert.RecordHash, "abc123def456")
	}
	if cert.DeviceMake != "Apple" {
		t.Errorf("device_make: got %q, want %q", cert.DeviceMake, "Apple")
	}
	if cert.LegacyReference == "" {
		t.Error("legacy reference should mention IEA s65B(4) supersession")
	}
}

func TestCertificateEngine_Validate(t *testing.T) {
	kp := crypto.NewFileKeyProvider(".")
	ce := NewCertificateEngine(&Evidence{}, NewChainEngine(kp, "test"), kp)

	cert := &BSAS63Certificate{
		RecordIdentifier:    "file.pdf",
		RecordHash:          "sha256hash",
		DeviceMake:          "Apple",
		DeviceModel:         "MacBook",
		ProductionMethod:    "manual-upload",
		ProducedBy:          "investigator",
		OperatingEnvironment: "investigation",
		NormalOperation:     true,
		AccuracyStatement:   "System operating normally.",
	}
	issues := ce.Validate(cert)
	if len(issues) != 0 {
		t.Errorf("expected no validation issues, got: %v", issues)
	}

	cert2 := &BSAS63Certificate{
		RecordIdentifier: "file.pdf",
	}
	issues2 := ce.Validate(cert2)
	if len(issues2) == 0 {
		t.Error("expected validation issues for incomplete cert")
	}
	if len(issues2) < 5 {
		t.Errorf("expected at least 5 issues, got %d", len(issues2))
	}
}

func TestCertificateEngine_ToTBSDocument(t *testing.T) {
	kp := crypto.NewFileKeyProvider(".")
	ce := NewCertificateEngine(&Evidence{}, NewChainEngine(kp, "test"), kp)

	cert := &BSAS63Certificate{
		CertificateID:    "QB-CERT-001",
		EvidenceID:       "QB-EVD-001",
		Status:           CertIssued,
		CreatedAt:        time.Now(),
		IssuedAt:         time.Now(),
		IssuedBy:         "Dr. Rao",
		IssuedByRole:     "Evidence Custodian",
		RecordIdentifier: "financial_record.pdf",
		RecordType:       "application/pdf",
		RecordSize:       10240,
		RecordHash:       "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		ProducedBy:       "Dr. Rao",
		ProductionMethod: "manual-upload",
		ProductionTime:   time.Now(),
		ProductionPlace:  "Digital evidence acquisition system",
		DeviceMake:       "Dell",
		DeviceModel:      "XPS 15",
		OSVersion:        "Windows 11",
		OperatingEnvironment: "investigation",
		NormalOperation:  true,
		AccuracyStatement:   "The electronic record was produced by a computer system operating normally.",
		CustodyChainHash: "chainhash123",
		CustodyEventCount: 3,
		VerificationStatus:  "VERIFIED",
		LegacyReference:     "IEA s65B(4) - superseded by BSA s63 effective 2024-07-01",
	}

	doc := ce.ToTBSDocument(cert)

	if !strings.Contains(doc, "Bharatiya Sakshya Adhiniyam") {
		t.Error("document should reference Bharatiya Sakshya Adhiniyam")
	}
	if !strings.Contains(doc, "Section 63") {
		t.Error("document should reference Section 63")
	}
	if !strings.Contains(doc, "QB-CERT-001") {
		t.Error("document should contain certificate ID")
	}
	if !strings.Contains(doc, "financial_record.pdf") {
		t.Error("document should contain record identifier")
	}
	if !strings.Contains(doc, "Dell") {
		t.Error("document should contain device make")
	}
	if !strings.Contains(doc, "ELECTRONIC RECORD IDENTIFICATION") {
		t.Error("document should have electronic record identification section")
	}
	if !strings.Contains(doc, "supersedes") {
		t.Error("document should have legacy note about IEA s65B(4) supersession")
	}
	if !strings.Contains(doc, "Dr. Rao") {
		t.Error("document should contain issued by name")
	}
}

func TestEvidence_IDCounter(t *testing.T) {
	a, _ := NewEngine(nil).Acquire([]byte("a"), AcquisitionRequest{OriginalName: "a.txt", Source: "test"})
	b, _ := NewEngine(nil).Acquire([]byte("b"), AcquisitionRequest{OriginalName: "b.txt", Source: "test"})

	if a.ID == b.ID {
		t.Error("evidence IDs should be unique")
	}
	if a.ID >= b.ID {
		t.Error("evidence IDs should be monotonically increasing")
	}
}

func TestVerificationService(t *testing.T) {
	vs := NewVerificationService()

	ev, _ := NewEngine(nil).Acquire([]byte("test evidence"), AcquisitionRequest{
		OriginalName: "test.pdf", Source: "upload", AcquiredBy: "user-1",
	})
	chain := NewChainEngine(nil, "test")
	chain.LogEvent(CustodyEventRequest{
		EvidenceID: ev.ID, Actor: "user-1", Action: "ACQUIRED",
		Details: map[string]interface{}{"file": "test.pdf"},
	})
	certEng := NewCertificateEngine(ev, chain, nil)
	cert, _ := certEng.Generate()

	vs.RegisterEvidence(ev, chain, cert)

	resp := vs.VerifyEvidence(VerificationRequest{EvidenceID: ev.ID})
	if resp.Status != "INTEGRITY VERIFIED" {
		t.Errorf("expected INTEGRITY VERIFIED, got %s", resp.Status)
	}
	if resp.CustodyEvents != 1 {
		t.Errorf("expected 1 custody event, got %d", resp.CustodyEvents)
	}
	if resp.CertificateID != cert.CertificateID {
		t.Errorf("certificate ID mismatch")
	}

	// Test not found
	resp2 := vs.VerifyEvidence(VerificationRequest{EvidenceID: "NONEXISTENT"})
	if resp2.Status != "NOT FOUND" {
		t.Errorf("expected NOT FOUND, got %s", resp2.Status)
	}
}
