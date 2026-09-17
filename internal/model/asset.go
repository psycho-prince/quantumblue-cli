package model

import (
    "encoding/json"
    "time"
)

type Asset struct {
    Id string `json:"id" db:"id"`
    OrganizationId string `json:"organizationId" db:"organizationId"`
    Kind string `json:"kind" db:"kind"`
    Identifier string `json:"identifier" db:"identifier"`
    Source string `json:"source" db:"source"`
    Criticality string `json:"criticality" db:"criticality"`
    FirstSeenAt time.Time `json:"firstSeenAt" db:"firstSeenAt"`
    LastSeenAt time.Time `json:"lastSeenAt" db:"lastSeenAt"`
    Active bool `json:"active" db:"active"`
    Metadata json.RawMessage `json:"metadata" db:"metadata"`
}
