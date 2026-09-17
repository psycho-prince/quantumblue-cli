package normalize

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/psycho-prince/pqc-sdk/internal/model"
)

func generateID(orgID, kind, identifier string) string {
	hash := sha256.Sum256([]byte(orgID + "|" + kind + "|" + identifier))
	return hex.EncodeToString(hash[:])
}

func NormalizeDomain(orgID, domain string) model.Asset {
	return model.Asset{
		Id:             generateID(orgID, "domain", domain),
		OrganizationId: orgID,
		Kind:           "domain",
		Identifier:     domain,
		Source:         "manual",
		Criticality:    "unknown",
		Active:         true,
	}
}

func NormalizeSubdomain(orgID, subdomain, source string) model.Asset {
	return model.Asset{
		Id:             generateID(orgID, "subdomain", subdomain),
		OrganizationId: orgID,
		Kind:           "subdomain",
		Identifier:     subdomain,
		Source:         source,
		Criticality:    "unknown",
		Active:         true,
	}
}

func CreateResolvesToEdge(fromAsset, toAsset model.Asset) model.AssetEdge {
	return model.AssetEdge{
		Id:          generateID(fromAsset.OrganizationId, "resolves_to", fromAsset.Id+"|"+toAsset.Id),
		FromAssetId: fromAsset.Id,
		ToAssetId:   toAsset.Id,
		Relation:    "resolves_to",
		Confidence:  1.0,
	}
}

func CreatePresentsCertEdge(fromAsset, toAsset model.Asset) model.AssetEdge {
	return model.AssetEdge{
		Id:          generateID(fromAsset.OrganizationId, "presents_cert", fromAsset.Id+"|"+toAsset.Id),
		FromAssetId: fromAsset.Id,
		ToAssetId:   toAsset.Id,
		Relation:    "presents_cert",
		Confidence:  1.0,
	}
}

func NormalizeHostFromIP(orgID, ip, source string) model.Asset {
	return model.Asset{
		Id:             generateID(orgID, "host", ip),
		OrganizationId: orgID,
		Kind:           "host",
		Identifier:     ip,
		Source:         source,
		Criticality:    "unknown",
		Active:         true,
	}
}

func NormalizeCertificate(orgID, fingerprint string) model.Asset {
	return model.Asset{
		Id:             generateID(orgID, "certificate", fingerprint),
		OrganizationId: orgID,
		Kind:           "certificate",
		Identifier:     strings.ToLower(fingerprint),
		Source:         "tls_probe",
		Criticality:    "unknown",
		Active:         true,
	}
}
