package model

import (
    "encoding/json"
    "testing"
)

func TestAuditEventRoundTrip(t *testing.T) {
    var obj AuditEvent
    data := []byte(`{}`) // minimal valid json for round trip
    if err := json.Unmarshal(data, &obj); err != nil {
        t.Fatalf("Failed to unmarshal AuditEvent: %v", err)
    }
    if _, err := json.Marshal(obj); err != nil {
        t.Fatalf("Failed to marshal AuditEvent: %v", err)
    }
}
