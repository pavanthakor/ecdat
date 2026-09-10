// Package decoys holds Go that MUST NOT produce a single Finding.
//
// Every entry here is a plausible false positive: prose that names an
// algorithm, an identifier that reads like a digest, a name-scoped RNG rule's
// non-key use, and a non-crypto import whose name looks cryptographic.
package decoys

import (
	"fmt"
	"math/rand"
	"strings"

	// A non-crypto package whose name looks cryptographic. Importing it is not
	// a cryptographic act and must not fire anything.
	"golang.org/x/text/secure/precis"
)

// MD5 and SHA-1 are named in this comment, and rsa.GenerateKey appears here
// too. A comment is documentation, not a call site: nothing may fire on it.
const documentation = "we migrated off MD5 and RC4 in 2019"

// Identifiers that read like crypto but hold nothing secret.
var (
	md5Column     = "legacy_md5_column"
	cipherName    = "display-name"
	sha1Migration = "completed"
	desTable      = "descriptions"
)

// A name-scoped RNG rule must NOT fire here: this is a jitter delay, not a key,
// token, secret or nonce.
func BackoffJitter(attempt int) int {
	jitter := rand.Intn(100)
	return attempt*1000 + jitter
}

// Shuffling a display list is not key generation either.
func ShuffleForDisplay(items []string) {
	rand.Shuffle(len(items), func(i, j int) {
		items[i], items[j] = items[j], items[i]
	})
}

func Normalise(name string) (string, error) {
	return precis.UsernameCaseMapped.String(name)
}

// Variables named like algorithms, holding non-crypto strings. Nothing may
// start matching on the NAME.
var (
	aes       = "advanced-editing-surface"
	transform = "uppercase-then-trim"
)

func Labels() string { return aes + transform }

func Describe() string {
	return fmt.Sprintf("%s / %s / %s / %s / %s",
		documentation, md5Column, cipherName, sha1Migration,
		strings.ToLower(desTable))
}
