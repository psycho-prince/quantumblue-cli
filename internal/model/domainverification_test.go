package model

import (
    "encoding/json"
    "testing"
)

func TestDomainVerificationRoundTrip(t *testing.T) {
    var obj DomainVerification
    data := []byte(`{}`) // minimal valid json for round trip
    if err := json.Unmarshal(data, &obj); err != nil {
        t.Fatalf("Failed to unmarshal DomainVerification: %v", err)
    }
    if _, err := json.Marshal(obj); err != nil {
        t.Fatalf("Failed to marshal DomainVerification: %v", err)
    }
}
