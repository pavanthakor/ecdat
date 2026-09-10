// A MEASURED LIMIT of constant propagation in Go -- and NOT the limit that was
// assumed (ADR-0028).
//
// Go's crypto API classifies algorithms with ATTRIBUTE and FUNCTION references
// -- elliptic.P384(), tls.VersionTLS10 -- and semgrep OSS propagates string
// literals only, so it does not follow them.
//
// The consequence is NOT that these call sites are invisible. The Go rules
// capture their metavariable without a regex constraint, so they still FIRE.
// What is lost is the PARAMETER: the capture binds the variable's name, so a
// P-384 key is reported as `curve: "curve"` rather than `curve: "P384"`.
//
// The scanner is honest about that on its own: the shape heuristic reads a
// lower-case bare name as unresolved, so these findings carry confidence 0.6
// and configurable=true instead of 1.0 and false. The artefact is inventoried;
// its parameter is marked as not-known rather than reported wrongly.
//
// That is why Go gets no const-prop conversion in ADR-0028: there is no
// classification to fix, only a parameter that cannot be resolved -- and
// resolving it would need Semgrep Pro.
package mustfire
import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
)

func keyThroughACurveVariable() (*ecdsa.PrivateKey, error) {
	curve := elliptic.P384()
	return ecdsa.GenerateKey(curve, rand.Reader)
}

func configThroughAVersionVariable() *tls.Config {
	version := uint16(tls.VersionTLS10)
	return &tls.Config{MinVersion: version}
}
