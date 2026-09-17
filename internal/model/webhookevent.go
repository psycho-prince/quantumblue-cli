package model

import (
    "encoding/json"
    "time"
)

type WebhookEvent struct {
    Id string `json:"id" db:"id"`
    Provider string `json:"provider" db:"provider"`
    EventId string `json:"eventId" db:"eventId"`
    EventType string `json:"eventType" db:"eventType"`
    Processed bool `json:"processed" db:"processed"`
    ProcessedAt *time.Time `json:"processedAt" db:"processedAt"`
    CreatedAt time.Time `json:"createdAt" db:"createdAt"`
    Payload json.RawMessage `json:"payload" db:"payload"`
}
