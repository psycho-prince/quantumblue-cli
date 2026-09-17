package model

import (
    "time"
)

type Anomaly struct {
    Id string `json:"id" db:"id"`
    ScanId string `json:"scanId" db:"scanId"`
    BaselineScanId string `json:"baselineScanId" db:"baselineScanId"`
    Kind string `json:"kind" db:"kind"`
    Description string `json:"description" db:"description"`
    Severity string `json:"severity" db:"severity"`
    CreatedAt time.Time `json:"createdAt" db:"createdAt"`
}
