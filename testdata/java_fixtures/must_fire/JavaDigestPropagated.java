package mustfire;

import java.security.MessageDigest;

public class JavaDigestPropagated {
    public MessageDigest weak() throws Exception {
        String algorithm = "MD5";
        return MessageDigest.getInstance(algorithm);
    }
}
