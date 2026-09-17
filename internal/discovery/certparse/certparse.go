package certparse

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/psycho-prince/pqc-sdk/internal/model"
)

func ParseChain(orgID, assetID string, chain []*x509.Certificate) ([]model.CertificateRecord, []model.CryptoUse) {
	var records []model.CertificateRecord
	var uses []model.CryptoUse

	for i, cert := range chain {
		fp := sha256.Sum256(cert.Raw)
		fpStr := hex.EncodeToString(fp[:])

		var keyBits int
		var curve string

		switch pub := cert.PublicKey.(type) {
		case *rsa.PublicKey:
			keyBits = pub.N.BitLen()
		case *ecdsa.PublicKey:
			keyBits = pub.Curve.Params().BitSize
			curve = pub.Curve.Params().Name
		case ed25519.PublicKey:
			keyBits = 256
		}

		selfSigned := false
		if cert.Subject.String() == cert.Issuer.String() {
			selfSigned = true
		}

		record := model.CertificateRecord{
			OrganizationId:     orgID,
			AssetId:            assetID,
			SerialNumber:       cert.SerialNumber.String(),
			FingerprintSHA256:  fpStr,
			Subject:            cert.Subject.String(),
			Issuer:             cert.Issuer.String(),
			Sans:               cert.DNSNames,
			NotBefore:          cert.NotBefore,
			NotAfter:           cert.NotAfter,
			SignatureAlgorithm: cert.SignatureAlgorithm.String(),
			PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
			IsCA:               cert.IsCA,
			ChainPosition:      i,
			SelfSigned:         selfSigned,
		}
		if keyBits > 0 {
			record.PublicKeyBits = &keyBits
		}
		records = append(records, record)

		// Emits for CryptoUse
		// PublicKeyAlgorithm + key => CryptoUse{role:"certificate", keyBits, curve}
		uses = append(uses, model.CryptoUse{
			OrganizationId: orgID,
			AssetId:        assetID,
			Primitive:      cert.PublicKeyAlgorithm.String(),
			Role:           "certificate",
			KeyBits:        &keyBits,
			Curve:          &curve,
			Location:       fmt.Sprintf("cert serial %s", cert.SerialNumber.String()),
		})

		// SignatureAlgorithm => CryptoUse{role:"signature"}
		sigAlg := cert.SignatureAlgorithm.String()
		if strings.Contains(sigAlg, "With") {
			parts := strings.Split(sigAlg, "With")
			if len(parts) == 2 {
				// E.g., SHA256WithRSA -> Hash: SHA256, Sig: RSA
				uses = append(uses, model.CryptoUse{
					OrganizationId: orgID,
					AssetId:        assetID,
					Primitive:      parts[1],
					Role:           "signature",
					Location:       fmt.Sprintf("cert serial %s", cert.SerialNumber.String()),
				})
			}
		}
	}

	return records, uses
}
