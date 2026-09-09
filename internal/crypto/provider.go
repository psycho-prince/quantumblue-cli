package crypto

import (
	"fmt"
	"os"
)

// KeyProvider abstracts key management, enabling HSM or file-based custody.
type KeyProvider interface {
	GenerateKey(id string) error
	Sign(id string, data []byte) ([]byte, error)
	Verify(id string, data, signature []byte) (bool, error)
	Destroy(id string) error
	Show(id string) ([]byte, error)
}

type FileKeyProvider struct {
	BaseDir string
}

func NewFileKeyProvider(baseDir string) *FileKeyProvider {
	return &FileKeyProvider{BaseDir: baseDir}
}

func (p *FileKeyProvider) keyPath(id string) string {
	if p.BaseDir == "" {
		return fmt.Sprintf("%s.key", id)
	}
	return fmt.Sprintf("%s/%s.key", p.BaseDir, id)
}

func (p *FileKeyProvider) pubPath(id string) string {
	if p.BaseDir == "" {
		return fmt.Sprintf("%s.pub", id)
	}
	return fmt.Sprintf("%s/%s.pub", p.BaseDir, id)
}

func (p *FileKeyProvider) GenerateKey(id string) error {
	pk, sk, err := GenerateIdentityKeyPair()
	if err != nil {
		return err
	}
	if err := os.WriteFile(p.keyPath(id), sk, 0600); err != nil {
		return err
	}
	return os.WriteFile(p.pubPath(id), pk, 0644)
}

func (p *FileKeyProvider) Sign(id string, data []byte) ([]byte, error) {
	sk, err := os.ReadFile(p.keyPath(id))
	if err != nil {
		return nil, err
	}
	return SignEnvelope(data, sk)
}

func (p *FileKeyProvider) Verify(id string, data, signature []byte) (bool, error) {
	pk, err := os.ReadFile(p.pubPath(id))
	if err != nil {
		return false, err
	}
	return VerifyEnvelope(data, signature, pk), nil
}

func (p *FileKeyProvider) Destroy(id string) error {
	path := p.keyPath(id)
	
	// Zero out file
	info, err := os.Stat(path)
	if err == nil {
		size := info.Size()
		
		// Pass 1: All zeros
		zeros := make([]byte, size)
		_ = os.WriteFile(path, zeros, 0600)
		
		// Pass 2: All ones
		ones := make([]byte, size)
		for i := range ones { ones[i] = 0xFF }
		_ = os.WriteFile(path, ones, 0600)
		
		// Pass 3: Pseudo-random (or just zeros again to clear)
		_ = os.WriteFile(path, zeros, 0600)
	}
	
	err1 := os.Remove(path)
	err2 := os.Remove(p.pubPath(id))
	if err1 != nil {
		return err1
	}
	return err2
}

func (p *FileKeyProvider) Show(id string) ([]byte, error) {
	return os.ReadFile(p.keyPath(id))
}
