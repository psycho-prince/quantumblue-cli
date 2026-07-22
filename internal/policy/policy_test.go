package policy

import (
	"testing"
)

func TestPolicy(t *testing.T) {
	p := DefaultPolicy()
	if !p.IsForbidden("md5") {
		t.Errorf("Expected md5 to be forbidden")
	}
	if p.IsForbidden("sha256") {
		t.Errorf("Expected sha256 to be allowed")
	}
}
