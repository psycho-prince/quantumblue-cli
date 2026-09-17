package model

import (
    "encoding/json"
    "testing"
)

func TestPaymentTransactionRoundTrip(t *testing.T) {
    var obj PaymentTransaction
    data := []byte(`{}`) // minimal valid json for round trip
    if err := json.Unmarshal(data, &obj); err != nil {
        t.Fatalf("Failed to unmarshal PaymentTransaction: %v", err)
    }
    if _, err := json.Marshal(obj); err != nil {
        t.Fatalf("Failed to marshal PaymentTransaction: %v", err)
    }
}
