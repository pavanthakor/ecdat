package mustfire

import (
	"crypto/aes"
	"crypto/cipher"
)

// A hard-coded AES key and IV. The sentinels below must reach NO Finding:
// tests/test_rules_go.py asserts the redaction guard holds.
var staticKey = []byte("GOSECRETSENTINEL0123456789abcdef")

var staticIV = []byte("GONOTAREALKEY123")

func EncryptWithStaticKey(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(staticKey)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, staticIV).CryptBlocks(out, plaintext)
	return out, nil
}
