// A MEASURED LIMIT of constant propagation, not a decoy (ADR-0028).
//
// Semgrep OSS propagates STRING literals through locals and constants. It does
// not propagate an ENUM or attribute reference, so a jjwt signing algorithm
// held in a `SignatureAlgorithm` variable is invisible -- and jjwt and auth0
// java-jwt both spell their algorithms that way, which is why the
// JWT-via-variable auth-bypass close that ADR-0028 achieved for JavaScript is
// NOT achievable for Java on this build.
//
// This file sits in must_not_fire because that is the behaviour today.
// Pretending otherwise in the answer key would hide a real gap. It is listed
// in `known_limits`, NOT in `decoys` -- a decoy should stay silent, and this
// should not.
package mustnotfire;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class EnumRefLimit {
    public String sign(java.security.Key key) {
        SignatureAlgorithm alg = SignatureAlgorithm.RS256;
        return Jwts.builder().setSubject("partner").signWith(alg, key).compact();
    }
}
