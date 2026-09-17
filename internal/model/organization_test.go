package model

import (
    "encoding/json"
    "testing"
)

func TestOrganizationRoundTrip(t *testing.T) {
    var obj Organization
    data := []byte(`{}`) // minimal valid json for round trip
    if err := json.Unmarshal(data, &obj); err != nil {
        t.Fatalf("Failed to unmarshal Organization: %v", err)
    }
    if _, err := json.Marshal(obj); err != nil {
        t.Fatalf("Failed to marshal Organization: %v", err)
    }
}
