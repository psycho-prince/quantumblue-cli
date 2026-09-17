package model

import (
    "encoding/json"
    "testing"
)

func TestEntitlementRoundTrip(t *testing.T) {
    var obj Entitlement
    data := []byte(`{}`) // minimal valid json for round trip
    if err := json.Unmarshal(data, &obj); err != nil {
        t.Fatalf("Failed to unmarshal Entitlement: %v", err)
    }
    if _, err := json.Marshal(obj); err != nil {
        t.Fatalf("Failed to marshal Entitlement: %v", err)
    }
}
