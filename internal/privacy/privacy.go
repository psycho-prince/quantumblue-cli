package privacy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/psycho-prince/pqc-sdk/internal/crypto"
)

// DataClassification represents the sensitivity level of data.
type DataClassification string

const (
	ClassPublic             DataClassification = "PUBLIC"
	ClassInternal           DataClassification = "INTERNAL"
	ClassConfidential       DataClassification = "CONFIDENTIAL"
	ClassHighlyConfidential DataClassification = "HIGHLY_CONFIDENTIAL"
	ClassEvidence           DataClassification = "EVIDENCE"
)

// ClassificationPolicy maps a classification to its required controls.
type ClassificationPolicy struct {
	MinEncryption    bool
	AccessLogging    bool
	DownloadControls bool
	ExportControls   bool
	RetentionDays    int
	SoftDeleteOnly   bool
}

var classificationPolicies = map[DataClassification]ClassificationPolicy{
	ClassPublic:             {MinEncryption: false, AccessLogging: true, DownloadControls: false, ExportControls: false, RetentionDays: 365, SoftDeleteOnly: false},
	ClassInternal:           {MinEncryption: true, AccessLogging: true, DownloadControls: false, ExportControls: false, RetentionDays: 365, SoftDeleteOnly: false},
	ClassConfidential:       {MinEncryption: true, AccessLogging: true, DownloadControls: true, ExportControls: true, RetentionDays: 730, SoftDeleteOnly: true},
	ClassHighlyConfidential: {MinEncryption: true, AccessLogging: true, DownloadControls: true, ExportControls: true, RetentionDays: 1095, SoftDeleteOnly: true},
	ClassEvidence:           {MinEncryption: true, AccessLogging: true, DownloadControls: true, ExportControls: true, RetentionDays: 2555, SoftDeleteOnly: true},
}

// PolicyFor returns the policy for a classification.
func PolicyFor(c DataClassification) (ClassificationPolicy, error) {
	p, ok := classificationPolicies[c]
	if !ok {
		return p, fmt.Errorf("unknown classification: %s", c)
	}
	return p, nil
}

// EncryptionService handles encryption at rest for classified data.
type EncryptionService struct {
	keyProvider crypto.KeyProvider
}

// NewEncryptionService creates an encryption service.
func NewEncryptionService(kp crypto.KeyProvider) *EncryptionService {
	if kp == nil {
		kp = crypto.NewFileKeyProvider(".")
	}
	return &EncryptionService{keyProvider: kp}
}

// Encrypt encrypts data using AES-256-GCM with a key from the provider.
func (es *EncryptionService) Encrypt(data []byte, keyID string) ([]byte, error) {
	key, err := es.keyProvider.Show(keyID)
	if err != nil {
		key, err = es.generateAndStoreKey(keyID)
		if err != nil {
			return nil, fmt.Errorf("key generation failed: %w", err)
		}
	}
	if len(key) < 32 {
		return nil, fmt.Errorf("key too short for AES-256: %d bytes", len(key))
	}
	key = key[:32]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, data, nil), nil
}

// Decrypt decrypts AES-256-GCM encrypted data.
func (es *EncryptionService) Decrypt(ciphertext []byte, keyID string) ([]byte, error) {
	key, err := es.keyProvider.Show(keyID)
	if err != nil {
		return nil, fmt.Errorf("key retrieval failed: %w", err)
	}
	if len(key) < 32 {
		return nil, fmt.Errorf("key too short for AES-256: %d bytes", len(key))
	}
	key = key[:32]
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// DataStore manages classified data with encryption and access control.
type DataStore struct {
	directory  string
	encryption *EncryptionService
	policy     map[DataClassification]ClassificationPolicy
	mu         sync.Mutex
}

// NewDataStore creates a data store with encryption.
func NewDataStore(dir string, kp crypto.KeyProvider) (*DataStore, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	es := NewEncryptionService(kp)
	return &DataStore{
		directory:  dir,
		encryption: es,
		policy:     classificationPolicies,
	}, nil
}

// StoreItem represents a stored classified data item.
type StoreItem struct {
	ID              string            `json:"id"`
	Classification  DataClassification `json:"classification"`
	EncryptedPayload []byte           `json:"encrypted_payload,omitempty"`
	PlainPayload    []byte            `json:"plain_payload,omitempty"`
	KeyID           string            `json:"key_id"`
	CreatedAt       time.Time         `json:"created_at"`
	DeletedAt       *time.Time        `json:"deleted_at,omitempty"`
}

// Store stores data with the given classification.
func (ds *DataStore) Store(classification DataClassification, payload []byte, keyID string) (*StoreItem, error) {
	policy, ok := ds.policy[classification]
	if !ok {
		return nil, fmt.Errorf("unknown classification: %s", classification)
	}
	item := &StoreItem{
		ID:             fmt.Sprintf("QB-DATA-%d", time.Now().UnixNano()),
		Classification: classification,
		KeyID:          keyID,
		CreatedAt:      time.Now(),
	}
	if policy.MinEncryption {
		encrypted, err := ds.encryption.Encrypt(payload, keyID)
		if err != nil {
			return nil, err
		}
		item.EncryptedPayload = encrypted
	} else {
		item.PlainPayload = payload
	}
	path := filepath.Join(ds.directory, item.ID+".qb")
	dataBytes, _ := json.Marshal(item)
	if err := os.WriteFile(path, dataBytes, 0600); err != nil {
		return nil, err
	}
	return item, nil
}

// Retrieve retrieves and decrypts a stored item.
func (ds *DataStore) Retrieve(id string) ([]byte, *StoreItem, error) {
	path := filepath.Join(ds.directory, id+".qb")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("item not found: %s", id)
	}
	var item StoreItem
	if err := json.Unmarshal(data, &item); err != nil {
		return nil, nil, err
	}
	if item.DeletedAt != nil {
		return nil, &item, fmt.Errorf("item %s has been deleted", id)
	}
	if len(item.EncryptedPayload) > 0 {
		decrypted, err := ds.encryption.Decrypt(item.EncryptedPayload, item.KeyID)
		if err != nil {
			return nil, &item, fmt.Errorf("decryption failed: %w", err)
		}
		return decrypted, &item, nil
	}
	return item.PlainPayload, &item, nil
}

// SoftDelete marks an item as deleted.
func (ds *DataStore) SoftDelete(id string) error {
	path := filepath.Join(ds.directory, id+".qb")
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var item StoreItem
	if err := json.Unmarshal(raw, &item); err != nil {
		return err
	}
	now := time.Now()
	item.DeletedAt = &now
	dataBytes, _ := json.Marshal(item)
	return os.WriteFile(path, dataBytes, 0600)
}

// Purge permanently removes a deleted item.
func (ds *DataStore) Purge(id string) error {
	path := filepath.Join(ds.directory, id+".qb")
	return os.Remove(path)
}

// RetentionCleanup removes items past their retention period.
func (ds *DataStore) RetentionCleanup() ([]string, error) {
	var removed []string
	entries, err := os.ReadDir(ds.directory)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(ds.directory, entry.Name()))
		if err != nil {
			continue
		}
		var item StoreItem
		if err := json.Unmarshal(raw, &item); err != nil {
			continue
		}
		policy, ok := ds.policy[item.Classification]
		if !ok {
			continue
		}
		expiry := item.CreatedAt.AddDate(0, 0, policy.RetentionDays)
		if time.Now().After(expiry) {
			if err := os.Remove(filepath.Join(ds.directory, entry.Name())); err != nil {
				continue
			}
			removed = append(removed, item.ID)
		}
	}
	return removed, nil
}

// generateAndStoreKey generates a 32-byte AES key and stores it via the key provider.
func (es *EncryptionService) generateAndStoreKey(keyID string) ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := es.keyProvider.WriteKey(keyID, key); err != nil {
		return nil, err
	}
	return key, nil
}
