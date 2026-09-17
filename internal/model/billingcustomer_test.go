package model

import (
    "encoding/json"
    "testing"
)

func TestBillingCustomerRoundTrip(t *testing.T) {
    var obj BillingCustomer
    data := []byte(`{}`) // minimal valid json for round trip
    if err := json.Unmarshal(data, &obj); err != nil {
        t.Fatalf("Failed to unmarshal BillingCustomer: %v", err)
    }
    if _, err := json.Marshal(obj); err != nil {
        t.Fatalf("Failed to marshal BillingCustomer: %v", err)
    }
}
