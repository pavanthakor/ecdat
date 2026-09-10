package mustfire;

import com.auth0.jwt.algorithms.Algorithm;

public class JavaJwtAuth0Rsa {
    public Algorithm signer(java.security.interfaces.RSAPublicKey pub,
                            java.security.interfaces.RSAPrivateKey priv) {
        return Algorithm.RSA256(pub, priv);
    }
}
