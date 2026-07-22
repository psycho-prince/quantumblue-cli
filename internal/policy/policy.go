package policy

// Policy defines forbidden cryptographic primitives
type Policy struct {
	Forbidden []string
}

func DefaultPolicy() *Policy {
	return &Policy{
		Forbidden: []string{"md5", "des", "rc4"},
	}
}

// IsForbidden checks if a primitive is in the forbidden list
func (p *Policy) IsForbidden(primitive string) bool {
	for _, f := range p.Forbidden {
		if f == primitive {
			return true
		}
	}
	return false
}
