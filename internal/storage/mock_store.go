package storage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"os"
)

type MockSecureStore struct {
	masterKey []byte
}

// NewMockStore simulates a hardware-backed store by loading a master key 
// from a restricted file.
func NewMockStore(keyPath string) (*MockSecureStore, error) {
	// In a real mobile app, this master key would stay inside the Secure Enclave.
	// For our sandbox, we'll read it from a local file.
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, errors.New("failed to load master wrapping key")
	}
	if len(key) != 32 {
		return nil, errors.New("invalid master key length")
	}
	return &MockSecureStore{masterKey: key}, nil
}

func (s *MockSecureStore) Wrap(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.masterKey)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Seal appends the ciphertext to the nonce (nonce + ciphertext + tag)
	return aesgcm.Seal(nonce, nonce, plaintext, nil), nil
}

func (s *MockSecureStore) Unwrap(wrapped []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.masterKey)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesgcm.NonceSize()
	if len(wrapped) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := wrapped[:nonceSize], wrapped[nonceSize:]
	return aesgcm.Open(nil, nonce, ciphertext, nil)
}
