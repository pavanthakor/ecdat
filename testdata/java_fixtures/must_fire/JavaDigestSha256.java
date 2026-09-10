package mustfire;

import java.security.MessageDigest;

// A control: coverage needs the correct choices inventoried too.
public class JavaDigestSha256 {
    public MessageDigest digest() throws Exception {
        return MessageDigest.getInstance("SHA-256");
    }
}
