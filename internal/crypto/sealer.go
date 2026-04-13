package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"os"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

const (
	MagicBytes     = "PQC!"
	VersionV2      = byte(0x02) // V2 includes signatures
	KyberCTSize    = 1088
	NonceSize      = 12
	ChunkSize      = 64 * 1024
	TagSize        = 16
	HeaderTotal    = 4 + 1 + KyberCTSize + NonceSize
	SignatureSize  = mode3.SignatureSize // ML-DSA-65 signature size
)

// SealSignedStream encrypts AND signs a file using post-quantum primitives.
func SealSignedStream(inputPath, outputPath string, pkKEM, skDSA, classicSecret []byte) error {
	// 1. Prepare standard PQC header and metadata
	ssPQ, ct, err := EncapsulateSecret(pkKEM)
	if err != nil {
		return err
	}
	key, _ := CombineSecretsQuantum(ssPQ, classicSecret, []byte("pqc-v2-signed"))

	// 2. Read plaintext
	plaintext, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}

	// 3. Encrypt data with AES-GCM
	block, _ := aes.NewCipher(key)
	aesgcm, _ := cipher.NewGCM(block)
	masterNonce := make([]byte, NonceSize)
	io.ReadFull(rand.Reader, masterNonce)

	encryptedPayload := aesgcm.Seal(nil, masterNonce, plaintext, nil)

	// 4. Construct the full envelope body for signing
	// [Magic][Version][KyberCT][MasterNonce][EncryptedData]
	var body []byte
	body = append(body, []byte(MagicBytes)...)
	body = append(body, VersionV2)
	body = append(body, ct...)
	body = append(body, masterNonce...)
	body = append(body, encryptedPayload...)

	// 5. Sign the entire body with ML-DSA-65
	sig, err := SignEnvelope(body, skDSA)
	if err != nil {
		return err
	}

	// 6. Write final signed envelope
	return os.WriteFile(outputPath, append(body, sig...), 0644)
}

// UnsealSignedStream verifies the signature and decrypts the file.
func UnsealSignedStream(inputPath, outputPath string, skKEM, pkDSA, classicSecret []byte) error {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}

	// 1. Verify Minimum Length (Header + Signature)
	if len(data) < HeaderTotal+SignatureSize {
		return errors.New("invalid or truncated signed envelope")
	}

	// 2. Separate Body and Signature
	body := data[:len(data)-SignatureSize]
	sig := data[len(data)-SignatureSize:]

	// 3. Authenticate with ML-DSA-65
	if !VerifyEnvelope(body, sig, pkDSA) {
		return errors.New("AUTHENTICATION FAILED: Invalid digital signature")
	}

	// 4. Extract Header from Verified Body
	if string(body[:4]) != MagicBytes || body[4] != VersionV2 {
		return errors.New("corrupted header or unsupported version")
	}

	ct := body[5 : 5+KyberCTSize]
	masterNonce := body[5+KyberCTSize : HeaderTotal]
	encryptedPayload := body[HeaderTotal:]

	// 5. Recover Keys and Decrypt
	ssPQ, err := DecapsulateSecret(skKEM, ct)
	if err != nil {
		return err
	}
	key, _ := CombineSecretsQuantum(ssPQ, classicSecret, []byte("pqc-v2-signed"))

	block, _ := aes.NewCipher(key)
	aesgcm, _ := cipher.NewGCM(block)

	plaintext, err := aesgcm.Open(nil, masterNonce, encryptedPayload, nil)
	if err != nil {
		return errors.New("decryption failed after verification")
	}

	return os.WriteFile(outputPath, plaintext, 0644)
}
