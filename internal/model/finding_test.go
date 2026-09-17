package model

import (
    "encoding/json"
    "testing"
)

func TestFindingRoundTrip(t *testing.T) {
    var obj Finding
    data := []byte(`{}`) // minimal valid json for round trip
    if err := json.Unmarshal(data, &obj); err != nil {
        t.Fatalf("Failed to unmarshal Finding: %v", err)
    }
    if _, err := json.Marshal(obj); err != nil {
        t.Fatalf("Failed to marshal Finding: %v", err)
    }
}
