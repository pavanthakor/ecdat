package mustfire;

import javax.crypto.Cipher;

// The transformation selected through a String variable. Java packs the
// algorithm, mode and padding into ONE token, so a rule that misses the
// propagated form loses all three -- including the ECB verdict, which is the
// highest-value finding in the Java pack.
public class JavaCipherPropagated {
    private static final String CONFIGURED_TRANSFORM = "AES/GCM/NoPadding";

    public Cipher ecbFromLocal() throws Exception {
        String transform = "AES/ECB/PKCS5Padding";
        return Cipher.getInstance(transform);
    }

    public Cipher gcmFromConstant() throws Exception {
        return Cipher.getInstance(CONFIGURED_TRANSFORM);
    }
}
