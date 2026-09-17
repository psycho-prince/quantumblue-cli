package model

import (
    "encoding/json"
    "testing"
)

func TestCryptoUseRoundTrip(t *testing.T) {
    var obj CryptoUse
    data := []byte(`{}`) // minimal valid json for round trip
    if err := json.Unmarshal(data, &obj); err != nil {
        t.Fatalf("Failed to unmarshal CryptoUse: %v", err)
    }
    if _, err := json.Marshal(obj); err != nil {
        t.Fatalf("Failed to marshal CryptoUse: %v", err)
    }
}
