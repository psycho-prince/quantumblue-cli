package model

import (
    "encoding/json"
    "testing"
)

func TestAlertRoundTrip(t *testing.T) {
    var obj Alert
    data := []byte(`{}`) // minimal valid json for round trip
    if err := json.Unmarshal(data, &obj); err != nil {
        t.Fatalf("Failed to unmarshal Alert: %v", err)
    }
    if _, err := json.Marshal(obj); err != nil {
        t.Fatalf("Failed to marshal Alert: %v", err)
    }
}
