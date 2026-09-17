package model

import (
    "encoding/json"
    "testing"
)

func TestAnomalyRoundTrip(t *testing.T) {
    var obj Anomaly
    data := []byte(`{}`) // minimal valid json for round trip
    if err := json.Unmarshal(data, &obj); err != nil {
        t.Fatalf("Failed to unmarshal Anomaly: %v", err)
    }
    if _, err := json.Marshal(obj); err != nil {
        t.Fatalf("Failed to marshal Anomaly: %v", err)
    }
}
