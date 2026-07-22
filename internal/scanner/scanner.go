package scanner

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"

	"github.com/psycho-prince/pqc-sdk/internal/policy"
)

type CBOMItem struct {
	Primitive string `json:"primitive"`
	Location  string `json:"location"`
	Severity  string `json:"severity"`
}

type CBOM struct {
	Version string     `json:"version"`
	Items   []CBOMItem `json:"items"`
}

type SimpleScanner struct {
	fset     *token.FileSet
	Findings []CBOMItem
}

func NewScanner() *SimpleScanner {
	return &SimpleScanner{
		fset:     token.NewFileSet(),
		Findings: []CBOMItem{},
	}
}

func (s *SimpleScanner) ScanFile(path string) error {
	node, err := parser.ParseFile(s.fset, path, nil, parser.ParseComments)
	if err != nil {
		return err
	}

	ast.Inspect(node, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			if sel.Sel.Name == "New" {
				primitive := fmt.Sprintf("%v", sel.X)
				p := policy.DefaultPolicy()
				severity := "medium"
				if p.IsForbidden(primitive) {
					severity = "CRITICAL"
				}

				s.Findings = append(s.Findings, CBOMItem{
					Primitive: primitive,
					Location:  s.fset.Position(call.Pos()).String(),
					Severity:  severity,
				})
			}
		}
		return true
	})
	return nil
}

func (s *SimpleScanner) GenerateCBOM() ([]byte, error) {
	cbom := CBOM{
		Version: "1.0",
		Items:   s.Findings,
	}
	return json.MarshalIndent(cbom, "", "  ")
}
