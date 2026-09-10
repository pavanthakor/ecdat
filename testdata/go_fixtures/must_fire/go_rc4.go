package mustfire

import "crypto/rc4"

func NewStream(key []byte) (*rc4.Cipher, error) {
	return rc4.NewCipher(key)
}
