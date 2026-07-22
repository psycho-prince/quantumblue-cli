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
		s := scanner.NewScanner()
		err := s.ScanFile(os.Args[2])
		if err != nil {
			fmt.Printf("Error scanning file: %v\n", err)
			return
		}
		cbom, err := s.GenerateCBOM()
		if err != nil {
			fmt.Printf("Error generating CBOM: %v\n", err)
			return
		}
		fmt.Println(string(cbom))
	case "daemon":
		if len(os.Args) < 3 {
			fmt.Println("Usage: qb daemon <port>")
			return
		}
		err := server.StartServer(os.Args[2])
		if err != nil {
			fmt.Printf("Error starting daemon: %v\n", err)
		}
	default:
		fmt.Println("Unknown command")
	}
}
