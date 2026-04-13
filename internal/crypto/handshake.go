package crypto

import (
	"fmt"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

// GenerateKyberKeyPair creates a new ML-KEM-768 keypair for the client.
func GenerateKyberKeyPair() ([]byte, []byte, error) {
	scheme := kyber768.Scheme()
	pk, sk, err := scheme.GenerateKeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("kyber keygen failed: %w", err)
	}

	pkBytes, _ := pk.MarshalBinary()
	skBytes, _ := sk.MarshalBinary()
	return pkBytes, skBytes, nil
}

// EncapsulateSecret generates a shared secret and a ciphertext for a public key.
// This represents the "Server" or "Infrastructure" responding to the client.
func EncapsulateSecret(pkBytes []byte) ([]byte, []byte, error) {
	scheme := kyber768.Scheme()
	pk, err := scheme.UnmarshalBinaryPublicKey(pkBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid public key: %w", err)
	}

	ct, ss, err := scheme.Encapsulate(pk)
	if err != nil {
		return nil, nil, fmt.Errorf("encapsulation failed: %w", err)
	}
	return ss, ct, nil
}

// DecapsulateSecret recovers the shared secret using the private key and ciphertext.
func DecapsulateSecret(skBytes, ctBytes []byte) ([]byte, error) {
	scheme := kyber768.Scheme()
	sk, err := scheme.UnmarshalBinaryPrivateKey(skBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}

	ss, err := scheme.Decapsulate(sk, ctBytes)
	if err != nil {
		return nil, fmt.Errorf("decapsulation failed: %w", err)
	}
	return ss, nil
}
