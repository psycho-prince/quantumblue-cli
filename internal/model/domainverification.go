package model

import (
    "time"
)

type DomainVerification struct {
    Id string `json:"id" db:"id"`
    OrganizationId string `json:"organizationId" db:"organizationId"`
    Domain string `json:"domain" db:"domain"`
    Method string `json:"method" db:"method"`
    Token string `json:"token" db:"token"`
    VerifiedAt *time.Time `json:"verifiedAt" db:"verifiedAt"`
    LastCheckedAt *time.Time `json:"lastCheckedAt" db:"lastCheckedAt"`
    CreatedAt time.Time `json:"createdAt" db:"createdAt"`
}
