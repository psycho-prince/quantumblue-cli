package model

import (
    "time"
)

type ApiKey struct {
    Id string `json:"id" db:"id"`
    OrganizationId string `json:"organizationId" db:"organizationId"`
    KeyHash string `json:"keyHash" db:"keyHash"`
    Label string `json:"label" db:"label"`
    CreatedAt time.Time `json:"createdAt" db:"createdAt"`
}
