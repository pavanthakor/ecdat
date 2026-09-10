package mustfire

import "math/rand"

// math/rand is a deterministic PRNG. Using it for a token is a key-recovery bug.
func NewSessionToken() int {
	token := rand.Int()
	return token
}
