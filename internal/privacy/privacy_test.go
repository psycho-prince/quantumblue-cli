package privacy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/psycho-prince/pqc-sdk/internal/crypto"
)

func TestPolicyFor(t *testing.T) {
	tests := []struct {
		cls      DataClassification
		ok       bool
		enc      bool
		retention int
	}{
		{ClassPublic, true, false, 365},
		{ClassInternal, true, true, 365},
		{ClassConfidential, true, true, 730},
		{ClassHighlyConfidential, true, true, 1095},
		{ClassEvidence, true, true, 2555},
	}

	for _, tt := range tests {
		p, err := PolicyFor(tt.cls)
		if err != nil {
			t.Errorf("PolicyFor(%s) returned error: %v", tt.cls, err)
		}
		if !tt.ok && err == nil {
			t.Errorf("PolicyFor(%s) expected error, got nil", tt.cls)
		}
		if tt.ok {
			if p.MinEncryption != tt.enc {
				t.Errorf("PolicyFor(%s).MinEncryption = %v, want %v", tt.cls, p.MinEncryption, tt.enc)
			}
			if p.RetentionDays != tt.retention {
				t.Errorf("PolicyFor(%s).RetentionDays = %d, want %d", tt.cls, p.RetentionDays, tt.retention)
			}
		}
	}

	_, err := PolicyFor(DataClassification("UNKNOWN"))
	if err == nil {
		t.Error("PolicyFor(UNKNOWN) expected error, got nil")
	}
}

func TestEncryptionRoundTrip(t *testing.T) {
	kp := crypto.NewFileKeyProvider(t.TempDir())
	es := NewEncryptionService(kp)

	if err := es.keyProvider.GenerateKey("test-key"); err != nil {
		t.Skipf("key generation skipped (may need ML-DSA): %v", err)
	}

	plaintext := []byte("sensitive electronic evidence data")
	ciphertext, err := es.Encrypt(plaintext, "test-key")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if len(ciphertext) <= len(plaintext) {
		t.Error("ciphertext should be larger than plaintext (nonce + tag)")
	}

	decrypted, err := es.Decrypt(ciphertext, "test-key")
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestDataStore_StoreAndRetrieve(t *testing.T) {
	dir := t.TempDir()
	ds, err := NewDataStore(dir, nil)
	if err != nil {
		t.Fatalf("NewDataStore: %v", err)
	}

	payload := []byte("classified evidence payload")

	// Public classification — no encryption
	item, err := ds.Store(ClassPublic, payload, "test-key")
	if err != nil {
		t.Fatalf("Store public: %v", err)
	}
	if item.EncryptedPayload != nil {
		t.Error("public classification should not be encrypted")
	}

	retrieved, _, err := ds.Retrieve(item.ID)
	if err != nil {
		t.Fatalf("Retrieve public: %v", err)
	}
	if string(retrieved) != string(payload) {
		t.Errorf("retrieved = %q, want %q", retrieved, payload)
	}

	// Confidential classification — encrypted
	item2, err := ds.Store(ClassConfidential, payload, "test-key")
	if err != nil {
		t.Fatalf("Store confidential: %v", err)
	}
	if item2.EncryptedPayload == nil {
		t.Error("confidential classification should be encrypted")
	}

	retrieved2, _, err := ds.Retrieve(item2.ID)
	if err != nil {
		t.Fatalf("Retrieve confidential: %v", err)
	}
	if string(retrieved2) != string(payload) {
		t.Errorf("retrieved = %q, want %q", retrieved2, payload)
	}
}

func TestDataStore_SoftDeleteAndPurge(t *testing.T) {
	dir := t.TempDir()
	ds, err := NewDataStore(dir, nil)
	if err != nil {
		t.Fatalf("NewDataStore: %v", err)
	}

	item, err := ds.Store(ClassInternal, []byte("data"), "test-key")
	if err != nil {
		t.Fatalf("Store: %v", err)
	}

	// Soft delete — item should be marked deleted but file remains
	if err := ds.SoftDelete(item.ID); err != nil {
		t.Fatalf("SoftDelete: %v", err)
	}
	_, _, err = ds.Retrieve(item.ID)
	if err == nil {
		t.Error("Retrieve after soft delete should fail")
	}

	// Purge — file should be removed
	if err := ds.Purge(item.ID); err == nil {
		purgePath := filepath.Join(dir, item.ID+".qb")
		if _, statErr := os.Stat(purgePath); statErr == nil {
			t.Error("file should be removed after purge")
		}
	}
}

func TestDataStore_RetentionCleanup(t *testing.T) {
	dir := t.TempDir()
	ds, err := NewDataStore(dir, nil)
	if err != nil {
		t.Fatalf("NewDataStore: %v", err)
	}

	// Store an item — brand new, shouldn't be cleaned (public retention = 365 days)
	if _, err := ds.Store(ClassPublic, []byte("old data"), "test-key"); err != nil {
		t.Fatal(err)
	}

	removed, err := ds.RetentionCleanup()
	if err != nil {
		t.Fatalf("RetentionCleanup: %v", err)
	}
	if len(removed) != 0 {
		t.Errorf("expected 0 removed items for new data, got %d", len(removed))
	}
}

func TestDataStore_UnknownClassification(t *testing.T) {
	dir := t.TempDir()
	ds, err := NewDataStore(dir, nil)
	if err != nil {
		t.Fatalf("NewDataStore: %v", err)
	}

	_, err = ds.Store(DataClassification("UNKNOWN_CLASS"), []byte("data"), "test-key")
	if err == nil {
		t.Error("Store with unknown classification should fail")
	}
}

func TestDataStore_PersistsAcrossRestarts(t *testing.T) {
	dir, err := os.MkdirTemp("", "privacy-persist")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	// First session
	ds1, err := NewDataStore(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	item, err := ds1.Store(ClassInternal, []byte("persistent data"), "test-key")
	if err != nil {
		t.Fatal(err)
	}

	// Second session — same directory
	ds2, err := NewDataStore(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	retrieved, _, err := ds2.Retrieve(item.ID)
	if err != nil {
		t.Fatalf("Retrieve in second session: %v", err)
	}
	if string(retrieved) != "persistent data" {
		t.Errorf("retrieved = %q, want %q", retrieved, "persistent data")
	}
}

func TestClassificationPolicy_DownloadAndExportControls(t *testing.T) {
	p, _ := PolicyFor(ClassConfidential)
	if !p.DownloadControls {
		t.Error("confidential should have download controls")
	}
	if !p.ExportControls {
		t.Error("confidential should have export controls")
	}

	p2, _ := PolicyFor(ClassPublic)
	if p2.DownloadControls || p2.ExportControls {
		t.Error("public should NOT have download/export controls")
	}
}

func TestDataStore_DeletedItemCannotBeRetrieved(t *testing.T) {
	dir := t.TempDir()
	ds, err := NewDataStore(dir, nil)
	if err != nil {
		t.Fatalf("NewDataStore: %v", err)
	}

	item, err := ds.Store(ClassConfidential, []byte("to be deleted"), "test-key")
	if err != nil {
		t.Fatalf("Store: %v", err)
	}

	if err := ds.SoftDelete(item.ID); err != nil {
		t.Fatal(err)
	}

	_, _, err = ds.Retrieve(item.ID)
	if err == nil {
		t.Error("should not be able to retrieve soft-deleted item")
	}
}
