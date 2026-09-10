package mustfire;

import java.security.spec.RSAKeyGenParameterSpec;
import java.math.BigInteger;

public class JavaBouncyCastleRsa {
    public RSAKeyGenParameterSpec spec() {
        return new RSAKeyGenParameterSpec(2048, BigInteger.valueOf(65537));
    }
}
