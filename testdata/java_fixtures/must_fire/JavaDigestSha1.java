package mustfire;

import java.security.MessageDigest;

public class JavaDigestSha1 {
    public MessageDigest digest() throws Exception {
        return MessageDigest.getInstance("SHA-1");
    }
}
