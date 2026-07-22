package analyzer

import (
	"go/ast"
	"go/parser"
	"go/token"
)

// FindCryptoCalls scans Go code for potential cryptographic function calls.
func FindCryptoCalls(filePath string) ([]string, error) {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, filePath, nil, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	var calls []string
	ast.Inspect(node, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if fun, ok := call.Fun.(*ast.SelectorExpr); ok {
				// Simplified check: looking for common crypto packages
				if pkg, ok := fun.X.(*ast.Ident); ok {
					if pkg.Name == "crypto" || pkg.Name == "rsa" || pkg.Name == "aes" {
						calls = append(calls, fun.Sel.Name)
					}
				}
			}
		}
		return true
	})
	return calls, nil
}
