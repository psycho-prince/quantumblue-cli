package crypto

import (
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

// GenerateIdentityKeyPair creates your unique Quantum-Safe ID using ML-DSA-65.
func GenerateIdentityKeyPair() (pkBytes, skBytes []byte, err error) {
	pk, sk, err := mode3.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ML-DSA keygen failed: %w", err)
	}
	pkBytes, _ = pk.MarshalBinary()
	skBytes, _ = sk.MarshalBinary()
	return pkBytes, skBytes, nil
}

// SignEnvelope authenticates the encrypted data.
func SignEnvelope(data, skBytes []byte) ([]byte, error) {
	var sk mode3.PrivateKey
	if err := sk.UnmarshalBinary(skBytes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal private key: %w", err)
	}
	
	signature := make([]byte, mode3.SignatureSize)
	mode3.SignTo(&sk, data, signature)
	return signature, nil
}

// VerifyEnvelope ensures the data hasn't been tampered with and comes from the expected author.
func VerifyEnvelope(data, sig, pkBytes []byte) bool {
	var pk mode3.PublicKey
	if err := pk.UnmarshalBinary(pkBytes); err != nil {
		return false
	}
	return mode3.Verify(&pk, data, sig)
}
