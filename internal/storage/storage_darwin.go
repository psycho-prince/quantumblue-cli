//go:build darwin && (ios || amd64)
package storage

import "errors"

func SaveSecureKey(key []byte) error {
	// TODO: Implement Security.framework bridge for Keychain/Secure Enclave
	return errors.New("ios/darwin secure storage not yet implemented")
}
