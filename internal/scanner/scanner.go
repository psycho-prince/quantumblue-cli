package scanner

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"

	"github.com/psycho-prince/pqc-sdk/internal/policy"
)

// CBOMItem represents a detected cryptographic finding.
type CBOMItem struct {
	Primitive string `json:"primitive"`
	Location  string `json:"location"`
	Severity  string `json:"severity"`
	Type      string `json:"type"` // e.g., "source", "binary", "config"
}

// DiscoveryScanner defines the interface for different types of discovery scans.
type DiscoveryScanner interface {
	Scan(path string) ([]CBOMItem, error)
}

// GoScanner implements DiscoveryScanner for Go source files.
type GoScanner struct {
	fset *token.FileSet
}

// NewGoScanner initializes a new GoScanner.
func NewGoScanner() *GoScanner {
	return &GoScanner{
		fset: token.NewFileSet(),
	}
}

// Scan inspects a Go file for potential crypto-related calls and imports.
func (s *GoScanner) Scan(path string) ([]CBOMItem, error) {
	findings := []CBOMItem{}
	node, err := parser.ParseFile(s.fset, path, nil, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	ast.Inspect(node, func(n ast.Node) bool {
		// Detect Imports
		if imp, ok := n.(*ast.ImportSpec); ok {
			importPath := imp.Path.Value
			if contains(importPath, "crypto/") {
				findings = append(findings, CBOMItem{
					Primitive: importPath,
					Location:  s.fset.Position(imp.Pos()).String(),
					Severity:  "info",
					Type:      "source",
				})
			}
		}

		// Detect Calls
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			primitive := fmt.Sprintf("%v", sel.X)
			
			p := policy.DefaultPolicy()
			severity := p.GetSeverity(primitive)

			findings = append(findings, CBOMItem{
				Primitive: primitive + "." + sel.Sel.Name,
				Location:  s.fset.Position(call.Pos()).String(),
				Severity:  severity,
				Type:      "source",
			})
		}
		return true
	})
	return findings, nil
}

func contains(s, substr string) bool {
	if len(s) < len(substr) {
		return false
	}
	// Simplified check: just check if the string contains the substring.
	// This avoids manual indexing issues.
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
