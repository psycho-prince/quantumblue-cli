package model

import (
    "encoding/json"
    "testing"
)

func TestScanRoundTrip(t *testing.T) {
    var obj Scan
    data := []byte(`{}`) // minimal valid json for round trip
    if err := json.Unmarshal(data, &obj); err != nil {
        t.Fatalf("Failed to unmarshal Scan: %v", err)
    }
    if _, err := json.Marshal(obj); err != nil {
        t.Fatalf("Failed to marshal Scan: %v", err)
    }
}
