package model

import (
    "encoding/json"
    "time"
)

type Scan struct {
    Id string `json:"id" db:"id"`
    OrganizationId string `json:"organizationId" db:"organizationId"`
    TargetName string `json:"targetName" db:"targetName"`
    BomSerialNumber string `json:"bomSerialNumber" db:"bomSerialNumber"`
    RawBom json.RawMessage `json:"rawBom" db:"rawBom"`
    CreatedAt time.Time `json:"createdAt" db:"createdAt"`
    ScanType string `json:"scanType" db:"scanType"`
    Status string `json:"status" db:"status"`
    StartedAt *time.Time `json:"startedAt" db:"startedAt"`
    CompletedAt *time.Time `json:"completedAt" db:"completedAt"`
    ErrorText *string `json:"errorText" db:"errorText"`
    RiskSummary json.RawMessage `json:"riskSummary" db:"riskSummary"`
}
