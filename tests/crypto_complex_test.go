package test

import (
	"crypto/aes"
	"crypto/md5"
	"crypto/rsa"
)

func main() {
	h := md5.New()
	block, _ := aes.NewCipher([]byte("key"))
	key, _ := rsa.GenerateKey(nil, 2048)
}
