package mustfire

import "crypto/sha256"

// A control: the inventory has to show what is CORRECT as well as what is not.
func Digest(data []byte) [32]byte {
	return sha256.Sum256(data)
}
