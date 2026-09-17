package model

import (
    "encoding/json"
    "testing"
)

func TestApiKeyRoundTrip(t *testing.T) {
    var obj ApiKey
    data := []byte(`{}`) // minimal valid json for round trip
    if err := json.Unmarshal(data, &obj); err != nil {
        t.Fatalf("Failed to unmarshal ApiKey: %v", err)
    }
    if _, err := json.Marshal(obj); err != nil {
        t.Fatalf("Failed to marshal ApiKey: %v", err)
    }
}
