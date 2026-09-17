package model

import (
    "encoding/json"
    "testing"
)

func TestAssetRoundTrip(t *testing.T) {
    var obj Asset
    data := []byte(`{}`) // minimal valid json for round trip
    if err := json.Unmarshal(data, &obj); err != nil {
        t.Fatalf("Failed to unmarshal Asset: %v", err)
    }
    if _, err := json.Marshal(obj); err != nil {
        t.Fatalf("Failed to marshal Asset: %v", err)
    }
}
