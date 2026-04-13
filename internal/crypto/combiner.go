package crypto

import (
	"crypto/hmac"
	"crypto/subtle"
	"errors"
	"fmt"

	"golang.org/x/crypto/sha3"
)

// Domain Separation Constants
const (
	ProtocolLabel = "QuantumBlue-V1"
	KDFFunction   = "KEM-Combiner"
)

// CombineSecretsQuantum uses HMAC-SHA3-256 to fuse classical (X25519) and 
// Post-Quantum (ML-KEM) secrets into a single 256-bit symmetric key.
func CombineSecretsQuantum(ssPQ, ssClassic, context []byte) ([]byte, error) {
	if len(ssPQ) == 0 || len(ssClassic) == 0 {
		return nil, errors.New("input secrets cannot be empty")
	}

	// 1. Prepare the Input Keying Material (IKM)
	ikm := make([]byte, 0, len(ssPQ)+len(ssClassic))
	ikm = append(ikm, ssPQ...)
	ikm = append(ikm, ssClassic...)

	// 2. Initialize HMAC-SHA3-256
	h := hmac.New(sha3.New256, []byte(KDFFunction))

	// 3. Absorb Input, Context, and Protocol Label
	if _, err := h.Write(ikm); err != nil {
		return nil, fmt.Errorf("failed to absorb IKM: %w", err)
	}
	if _, err := h.Write(context); err != nil {
		return nil, fmt.Errorf("failed to absorb context: %w", err)
	}
	if _, err := h.Write([]byte(ProtocolLabel)); err != nil {
		return nil, fmt.Errorf("failed to absorb label: %w", err)
	}

	// 4. Finalize and extract the 32-byte (256-bit) key
	finalKey := h.Sum(nil)

	// 5. CRITICAL: Memory Sanitization
	SafeZero(ikm)

	return finalKey, nil
}

// SafeZero ensures sensitive buffers are cleared from memory.
func SafeZero(b []byte) {
	if len(b) == 0 {
		return
	}
	for i := range b {
		b[i] = 0
	}
	_ = subtle.ConstantTimeByteEq(b[0], b[0])
}
