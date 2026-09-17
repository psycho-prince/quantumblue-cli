package model

import (
    "encoding/json"
    "testing"
)

func TestCertificateRecordRoundTrip(t *testing.T) {
    var obj CertificateRecord
    data := []byte(`{}`) // minimal valid json for round trip
    if err := json.Unmarshal(data, &obj); err != nil {
        t.Fatalf("Failed to unmarshal CertificateRecord: %v", err)
    }
    if _, err := json.Marshal(obj); err != nil {
        t.Fatalf("Failed to marshal CertificateRecord: %v", err)
    }
}
