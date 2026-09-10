package mustfire;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class JavaJwtJjwt {
    public String issue(java.security.Key key) {
        return Jwts.builder().setSubject("partner").signWith(SignatureAlgorithm.RS256, key).compact();
    }
}
