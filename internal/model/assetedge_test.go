package model

import (
    "encoding/json"
    "testing"
)

func TestAssetEdgeRoundTrip(t *testing.T) {
    var obj AssetEdge
    data := []byte(`{}`) // minimal valid json for round trip
    if err := json.Unmarshal(data, &obj); err != nil {
        t.Fatalf("Failed to unmarshal AssetEdge: %v", err)
    }
    if _, err := json.Marshal(obj); err != nil {
        t.Fatalf("Failed to marshal AssetEdge: %v", err)
    }
}
