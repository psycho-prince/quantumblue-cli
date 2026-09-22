package evidence

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/psycho-prince/pqc-sdk/internal/crypto"
)

// CustodyEvent represents a single event in the chain of custody.
type CustodyEvent struct {
	EventID       string          `json:"event_id"`
	Timestamp     time.Time       `json:"timestamp"`
	Actor         string          `json:"actor"`
	Action        string          `json:"action"`
	EvidenceID    string          `json:"evidence_id"`
	PreviousHash  string          `json:"previous_hash"`
	EventHash     string          `json:"event_hash"`
	Signature     []byte          `json:"signature,omitempty"`
	SignatureAlgo string          `json:"signature_algorithm,omitempty"`
	Details       json.RawMessage `json:"details,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
}

// CustodyChain is the chain for one evidence item.
type CustodyChain struct {
	EvidenceID string         `json:"evidence_id"`
	Events     []CustodyEvent `json:"events"`
	CurrentHash string        `json:"current_hash"`
	Verified   bool           `json:"verified"`
	LastEvent  *CustodyEvent  `json:"last_event,omitempty"`
}

// CustodyEventRequest is input for logging a custody event.
type CustodyEventRequest struct {
	EvidenceID     string
	Actor          string
	Action         string
	Details        map[string]interface{}
	Signature      []byte
	SignatureAlgo  string
	KeyID          string // for crypto signing
}

// ChainEngine manages custody chains.
type ChainEngine struct {
	keyProvider crypto.KeyProvider
	keyID       string
	events      map[string][]CustodyEvent
}

// NewChainEngine creates a chain engine.
func NewChainEngine(kp crypto.KeyProvider, keyID string) *ChainEngine {
	if kp == nil {
		kp = crypto.NewFileKeyProvider(".")
	}
	if keyID == "" {
		keyID = "quantumblue-custody"
	}
	return &ChainEngine{
		keyProvider: kp,
		keyID:       keyID,
		events:      make(map[string][]CustodyEvent),
	}
}

// LogEvent appends a custody event.
func (ce *ChainEngine) LogEvent(req CustodyEventRequest) (*CustodyEvent, error) {
	events := ce.events[req.EvidenceID]

	prevHash := ""
	if len(events) > 0 {
		last := &events[len(events)-1]
		prevHash = hashEventForChain(last)
	}

	now := time.Now()
	event := CustodyEvent{
		EventID:      fmt.Sprintf("QB-CE-%s-%s", req.EvidenceID, formatTS(now)),
		Timestamp:    now,
		Actor:        req.Actor,
		Action:       req.Action,
		EvidenceID:   req.EvidenceID,
		PreviousHash: prevHash,
		Details:      toJSON(req.Details),
		CreatedAt:    now,
	}

	eventHash := hashEventForChain(&event)
	event.EventHash = eventHash

	// Sign critical events
	if isCriticalAction(req.Action) && ce.keyProvider != nil {
		sig, err := ce.keyProvider.Sign(ce.keyID, []byte(eventHash))
		if err == nil {
			event.Signature = sig
			event.SignatureAlgo = "ML-DSA-65"
		} else {
			// Fallback HMAC
			event.Signature = hmacSHA256(ce.keyID, eventHash)
			event.SignatureAlgo = "SHA256-HMAC"
		}
	} else {
		event.Signature = hmacSHA256(ce.keyID, eventHash)
		event.SignatureAlgo = "SHA256-HMAC"
	}

	events = append(events, event)
	ce.events[req.EvidenceID] = events

	// Return pointer to the slice element (stable address)
	result := &ce.events[req.EvidenceID][len(ce.events[req.EvidenceID])-1]
	return result, nil
}

// VerifyChain checks the chain integrity.
func (ce *ChainEngine) VerifyChain(evidenceID string) (*CustodyChain, error) {
	events := ce.events[evidenceID]
	if len(events) == 0 {
		return &CustodyChain{EvidenceID: evidenceID}, fmt.Errorf("no custody events for %s", evidenceID)
	}

	chain := &CustodyChain{
		EvidenceID: evidenceID,
		Events:     events,
	}

	expectedPrev := ""
	for i, event := range events {
		computed := hashEventForChain(&event)
		if computed != event.EventHash {
			return chain, fmt.Errorf("chain broken at event %d: hash mismatch", i)
		}
		if i > 0 && event.PreviousHash != expectedPrev {
			return chain, fmt.Errorf("chain broken at event %d: previous hash mismatch", i)
		}
		expectedPrev = event.EventHash
	}

	chain.Verified = true
	last := &events[len(events)-1]
	chain.CurrentHash = last.EventHash
	chain.LastEvent = last

	return chain, nil
}

// GetChain returns the chain without full verification.
func (ce *ChainEngine) GetChain(evidenceID string) *CustodyChain {
	events := ce.events[evidenceID]
	if len(events) == 0 {
		return &CustodyChain{EvidenceID: evidenceID}
	}
	last := events[len(events)-1]
	return &CustodyChain{
		EvidenceID: evidenceID,
		Events:     events,
		CurrentHash: hashEventForChain(&last),
		LastEvent:  &last,
	}
}

// hashEventForChain computes SHA-256 of the event excluding EventHash and Signature.
func hashEventForChain(event *CustodyEvent) string {
	m := map[string]interface{}{
		"event_id":     event.EventID,
		"timestamp":    event.Timestamp,
		"actor":        event.Actor,
		"action":       event.Action,
		"evidence_id":  event.EvidenceID,
		"previous_hash": event.PreviousHash,
		"details":      event.Details,
		"created_at":   event.CreatedAt,
	}
	data, _ := json.Marshal(m)
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func hmacSHA256(key, data string) []byte {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(data))
	return mac.Sum(nil)
}

func isCriticalAction(action string) bool {
	switch action {
	case "ACQUIRED", "HASHED", "SIGNED", "EXPORTED", "VERIFIED", "ARCHIVED":
		return true
	}
	return false
}

func formatTS(t time.Time) string {
	return t.Format("20060102150405")
}

func toJSON(v interface{}) json.RawMessage {
	if v == nil {
		return []byte("{}")
	}
	data, _ := json.Marshal(v)
	return data
}
