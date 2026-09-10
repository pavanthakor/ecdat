package decoys

// must_not_fire (ADR-0034): near misses. Each fails exactly ONE corroboration
// signal and must not fire.

import (
	"crypto/aes"
	"crypto/sha256"

	"golang.org/x/crypto/pbkdf2"
)

// Right name, right length, no entropy.
var repeatingKey = "deadbeefdeadbeefdeadbeefdeadbeef"

// Right name, random, 31 characters: under the 32-character bar.
var shortHexKey = "94ffbb34ee948f9a077d4ba0b1d488b"

// Random and 64 characters, but nothing in the NAME says key: a digest.
var releaseChecksum = "35be2d4514d0db85faeabd7e43e30049b5ee915efb66e62847a324bae3a7de57"

// A KDF's output is not its salt: `taint_assume_safe_functions` stops the salt
// literal flowing through pbkdf2.Key into the cipher.
func KeyFromPassword(password string) error {
	key := pbkdf2.Key([]byte(password), []byte("GONEARMISSstaticSaltValue"), 600000, 32, sha256.New)
	_, err := aes.NewCipher(key)
	return err
}

// Assembled from a constant and a runtime value: a part is not the key.
func TenantCipher(tenantSecret string) error {
	_, err := aes.NewCipher([]byte("GONEARMISSprefix" + tenantSecret))
	return err
}

func Names() string { return repeatingKey + shortHexKey + releaseChecksum }
