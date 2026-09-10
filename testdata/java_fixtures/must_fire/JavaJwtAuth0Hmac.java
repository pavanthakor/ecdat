package mustfire;

import com.auth0.jwt.algorithms.Algorithm;

public class JavaJwtAuth0Hmac {
    public Algorithm signer(String secret) {
        return Algorithm.HMAC256(secret);
    }
}
