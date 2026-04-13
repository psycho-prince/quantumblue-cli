//go:build !android && !darwin
package storage

import (
	"fmt"
	"os"
)

func SaveSecureKey(key []byte) error {
	fmt.Println("⚠️ Falling back to file-system storage (NOT SECURE FOR PRODUCTION)")
	return os.WriteFile("pqc_key.bin", key, 0600)
}
