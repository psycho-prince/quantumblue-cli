package test

import (
	"crypto/des"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
)

func main() {
	_ = md5.New()
	_, _ = des.NewCipher(make([]byte, 8))
	_, _ = rsa.GenerateKey(rand.Reader, 2048)
}
