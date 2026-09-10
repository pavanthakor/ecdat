package mustfire;

import java.security.Signature;

// SHA-1 in the signature: the digest is collision-broken, so the signature is
// forgeable regardless of RSA key size.
public class JavaSignatureSha1Rsa {
    public Signature legacySigner() throws Exception {
        return Signature.getInstance("SHA1withRSA");
    }
}
