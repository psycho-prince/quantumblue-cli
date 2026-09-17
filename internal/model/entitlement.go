package model

import (
    "encoding/json"
)

type Entitlement struct {
    Id string `json:"id" db:"id"`
    OrganizationId string `json:"organizationId" db:"organizationId"`
    PlanCode string `json:"planCode" db:"planCode"`
    Source string `json:"source" db:"source"`
    MaxDomains int `json:"maxDomains" db:"maxDomains"`
    MaxAssets int `json:"maxAssets" db:"maxAssets"`
    ScansPerMonth int `json:"scansPerMonth" db:"scansPerMonth"`
    Features json.RawMessage `json:"features" db:"features"`
}
