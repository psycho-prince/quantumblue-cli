package model

import (
    "time"
)

type AssetEdge struct {
    Id string `json:"id" db:"id"`
    FromAssetId string `json:"fromAssetId" db:"fromAssetId"`
    ToAssetId string `json:"toAssetId" db:"toAssetId"`
    Relation string `json:"relation" db:"relation"`
    Confidence float64 `json:"confidence" db:"confidence"`
    CreatedAt time.Time `json:"createdAt" db:"createdAt"`
}
