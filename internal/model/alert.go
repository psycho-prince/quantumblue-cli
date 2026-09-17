package model

import (
    "time"
)

type Alert struct {
    Id string `json:"id" db:"id"`
    OrganizationId string `json:"organizationId" db:"organizationId"`
    Severity string `json:"severity" db:"severity"`
    Kind string `json:"kind" db:"kind"`
    Title string `json:"title" db:"title"`
    Body string `json:"body" db:"body"`
    AssetId *string `json:"assetId" db:"assetId"`
    FindingRef *string `json:"findingRef" db:"findingRef"`
    DeliveredAt *time.Time `json:"deliveredAt" db:"deliveredAt"`
    AcknowledgedAt *time.Time `json:"acknowledgedAt" db:"acknowledgedAt"`
    CreatedAt time.Time `json:"createdAt" db:"createdAt"`
}
