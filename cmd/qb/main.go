package main

import (
	"fmt"
	"os"
	"github.com/psycho-prince/pqc-sdk/internal/scanner"
	"github.com/psycho-prince/pqc-sdk/internal/server"
)

func main() {
	fmt.Println("QuantumBlue CLI v2.0.0-alpha")
	
	if len(os.Args) < 2 {
		fmt.Println("Usage: qb [scan <file.go> | daemon <port>]")
		return
	}

	switch os.Args[1] {
	case "scan":
		if len(os.Args) < 3 {
			fmt.Println("Usage: qb scan <file.go>")
			return
		}
		s := scanner.NewGoScanner()
		findings, err := s.Scan(os.Args[2])
		if err != nil {
			fmt.Printf("Error scanning file: %v\n", err)
			return
		}
		// For now just print findings
		for _, f := range findings {
			fmt.Printf("Found: %s at %s\n", f.Primitive, f.Location)
		}
	case "daemon":
		if len(os.Args) < 3 {
			fmt.Println("Usage: qb daemon <port>")
			return
		}
		dsn := os.Getenv("DATABASE_URL")
		err := server.StartServer(os.Args[2], dsn)
		if err != nil {
			fmt.Printf("Error starting daemon: %v\n", err)
		}
	default:
		fmt.Println("Unknown command")
	}
}
