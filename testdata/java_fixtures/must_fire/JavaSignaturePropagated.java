package mustfire;

import java.security.Signature;

// SHA1withRSA behind a variable. The digest is what is broken, and the
// weak-hash rule is the one that carries `flagged` -- so missing the
// propagated form loses the flag as well as the finding.
public class JavaSignaturePropagated {
    public Signature legacy() throws Exception {
        String transform = "SHA1withRSA";
        return Signature.getInstance(transform);
    }
}
