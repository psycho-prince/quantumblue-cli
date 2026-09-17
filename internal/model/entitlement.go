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

func (e *Entitlement) HasFeature(name string) bool {
	if len(e.Features) == 0 {
		return false
	}
	var feats map[string]bool
	if err := json.Unmarshal(e.Features, &feats); err != nil {
		return false
	}
	v, ok := feats[name]
	return ok && v
}

// FeaturesFromString converts a JSON string to json.RawMessage for Entitlement.Features.
func FeaturesFromString(s string) json.RawMessage {
	return json.RawMessage(s)
}
