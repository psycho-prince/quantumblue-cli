package model

import (
    "encoding/json"
    "time"
)

type AuditEvent struct {
    Id string `json:"id" db:"id"`
    OrganizationId string `json:"organizationId" db:"organizationId"`
    Action string `json:"action" db:"action"`
    Details json.RawMessage `json:"details" db:"details"`
    CreatedAt time.Time `json:"createdAt" db:"createdAt"`
}
