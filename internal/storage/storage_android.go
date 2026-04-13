//go:build android
package storage

import "errors"

func SaveSecureKey(key []byte) error {
	// TODO: Implement JNI bridge to Android Hardware Keystore
	return errors.New("android keystore not yet implemented")
}
