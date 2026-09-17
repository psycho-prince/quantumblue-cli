package model

import (
    "encoding/json"
    "testing"
)

func TestWebhookEventRoundTrip(t *testing.T) {
    var obj WebhookEvent
    data := []byte(`{}`) // minimal valid json for round trip
    if err := json.Unmarshal(data, &obj); err != nil {
        t.Fatalf("Failed to unmarshal WebhookEvent: %v", err)
    }
    if _, err := json.Marshal(obj); err != nil {
        t.Fatalf("Failed to marshal WebhookEvent: %v", err)
    }
}
