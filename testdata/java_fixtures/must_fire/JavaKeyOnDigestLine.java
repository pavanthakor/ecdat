package mustfire;

import java.security.MessageDigest;

public class JavaKeyOnDigestLine {
    // THE CROSS-RULE CASE, on ONE LINE. `java-digest-md5` matches this line and
    // has no `redact` flag and no idea a secret is on it -- the key-material
    // rule is not what protects the sentinel here. This is the shape the
    // independent scrub in scanners/source/_redact exists for.
    public byte[] fingerprint() throws Exception {
        return MessageDigest.getInstance("MD5").digest("JAVASECRETSENTINELabcdef0123456789".getBytes("UTF-8"));
    }
}
