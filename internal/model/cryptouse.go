package model

import (
    "encoding/json"
)

type CryptoUse struct {
    Id string `json:"id" db:"id"`
    OrganizationId string `json:"organizationId" db:"organizationId"`
    AssetId string `json:"assetId" db:"assetId"`
    Primitive string `json:"primitive" db:"primitive"`
    Role string `json:"role" db:"role"`
    QuantumStatus string `json:"quantumStatus" db:"quantumStatus"`
    Location string `json:"location" db:"location"`
    Evidence json.RawMessage `json:"evidence" db:"evidence"`
}
