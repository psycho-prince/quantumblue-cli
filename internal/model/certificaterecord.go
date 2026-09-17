package model

import (
    "time"
)

type CertificateRecord struct {
    Id string `json:"id" db:"id"`
    OrganizationId string `json:"organizationId" db:"organizationId"`
    AssetId string `json:"assetId" db:"assetId"`
    SerialNumber string `json:"serialNumber" db:"serialNumber"`
    FingerprintSHA256 string `json:"fingerprintSHA256" db:"fingerprintSHA256"`
    Subject string `json:"subject" db:"subject"`
    Issuer string `json:"issuer" db:"issuer"`
    Sans []string `json:"sans" db:"sans"`
    NotBefore time.Time `json:"notBefore" db:"notBefore"`
    NotAfter time.Time `json:"notAfter" db:"notAfter"`
    SignatureAlgorithm string `json:"signatureAlgorithm" db:"signatureAlgorithm"`
    PublicKeyAlgorithm string `json:"publicKeyAlgorithm" db:"publicKeyAlgorithm"`
    PublicKeyBits *int `json:"publicKeyBits" db:"publicKeyBits"`
    IsCA bool `json:"isCA" db:"isCA"`
    ChainPosition int `json:"chainPosition" db:"chainPosition"`
    SelfSigned bool `json:"selfSigned" db:"selfSigned"`
}
