package mustfire;

import java.security.MessageDigest;

public class JavaDigestMd5 {
    public MessageDigest digest() throws Exception {
        return MessageDigest.getInstance("MD5");
    }
}
