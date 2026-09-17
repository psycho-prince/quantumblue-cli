package model

import (
    "time"
)

type ScheduledJob struct {
    Id string `json:"id" db:"id"`
    OrganizationId string `json:"organizationId" db:"organizationId"`
    Kind string `json:"kind" db:"kind"`
    TargetRef string `json:"targetRef" db:"targetRef"`
    CronExpr string `json:"cronExpr" db:"cronExpr"`
    NextRunAt time.Time `json:"nextRunAt" db:"nextRunAt"`
    FailureCount int `json:"failureCount" db:"failureCount"`
    Enabled bool `json:"enabled" db:"enabled"`
}
