package policy

import (
	"bytes"
	"embed"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/psycho-prince/pqc-sdk/internal/model"
)

//go:embed rules/*.yaml
var rulesFS embed.FS

type Match struct {
	Primitive string                 `yaml:"primitive"`
	Role      string                 `yaml:"role"`
	KeyBits   map[string]interface{} `yaml:"keyBits,omitempty"`
}

type Rule struct {
	ID            string   `yaml:"id"`
	Match         Match    `yaml:"match"`
	QuantumStatus string   `yaml:"quantumStatus"`
	BaseSeverity  string   `yaml:"baseSeverity"`
	Rationale     string   `yaml:"rationale"`
	References    []string `yaml:"references"`
	Migration     string   `yaml:"migration,omitempty"`
}

type Engine struct {
	Rules []Rule
}

func NewEngine() (*Engine, error) {
	entries, err := rulesFS.ReadDir("rules")
	if err != nil {
		return nil, err
	}

	var allRules []Rule
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		data, err := rulesFS.ReadFile("rules/" + entry.Name())
		if err != nil {
			return nil, err
		}
		var fileRules []Rule
		if err := yaml.NewDecoder(bytes.NewReader(data)).Decode(&fileRules); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", entry.Name(), err)
		}
		allRules = append(allRules, fileRules...)
	}

	return &Engine{Rules: allRules}, nil
}

type ScoreExplanation struct {
	RuleID        string
	QuantumStatus string
	Risk          string
	Rationale     string
	Migration     string
	// Could include breakdown of asset criticality vs base severity later
}

func (e *Engine) ScoreFinding(finding model.CryptoUse) *ScoreExplanation {
	for _, r := range e.Rules {
		if !strings.EqualFold(r.Match.Primitive, finding.Primitive) {
			continue
		}
		if r.Match.Role != "" && !strings.EqualFold(r.Match.Role, finding.Role) {
			continue
		}

		if len(r.Match.KeyBits) > 0 {
			if finding.KeyBits == nil {
				continue
			}
			bits := *finding.KeyBits
			matchesBits := true
			if lt, ok := r.Match.KeyBits["lt"].(int); ok && bits >= lt {
				matchesBits = false
			}
			if gte, ok := r.Match.KeyBits["gte"].(int); ok && bits < gte {
				matchesBits = false
			}
			if !matchesBits {
				continue
			}
		}

		return &ScoreExplanation{
			RuleID:        r.ID,
			QuantumStatus: r.QuantumStatus,
			Risk:          r.BaseSeverity,
			Rationale:     strings.TrimSpace(r.Rationale),
			Migration:     r.Migration,
		}
	}

	return &ScoreExplanation{
		RuleID:        "unknown-primitive",
		QuantumStatus: "unknown",
		Risk:          "medium",
		Rationale:     "Primitive not matched by any policy rule.",
	}
}
