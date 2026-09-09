package main

import (
	"fmt"
	"os"

	"github.com/psycho-prince/pqc-sdk/internal/crypto"
)

func main() {
	provider := crypto.NewFileKeyProvider(".")
	err := provider.GenerateKey("real-key")
	if err != nil {
		fmt.Println("Error generating key:", err)
		os.Exit(1)
	}
	fmt.Println("Generated real-key")
}
