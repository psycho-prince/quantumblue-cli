package model

import (
    "encoding/json"
    "testing"
)

func TestSubscriptionRoundTrip(t *testing.T) {
    var obj Subscription
    data := []byte(`{}`) // minimal valid json for round trip
    if err := json.Unmarshal(data, &obj); err != nil {
        t.Fatalf("Failed to unmarshal Subscription: %v", err)
    }
    if _, err := json.Marshal(obj); err != nil {
        t.Fatalf("Failed to marshal Subscription: %v", err)
    }
}
