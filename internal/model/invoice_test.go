package model

import (
    "encoding/json"
    "testing"
)

func TestInvoiceRoundTrip(t *testing.T) {
    var obj Invoice
    data := []byte(`{}`) // minimal valid json for round trip
    if err := json.Unmarshal(data, &obj); err != nil {
        t.Fatalf("Failed to unmarshal Invoice: %v", err)
    }
    if _, err := json.Marshal(obj); err != nil {
        t.Fatalf("Failed to marshal Invoice: %v", err)
    }
}
