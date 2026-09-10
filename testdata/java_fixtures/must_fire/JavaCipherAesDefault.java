package mustfire;

import javax.crypto.Cipher;

public class JavaCipherAesDefault {
    // No mode given. The SunJCE provider defaults to ECB, so this is ECB
    // without the word appearing anywhere in the source.
    public Cipher implicitEcb() throws Exception {
        return Cipher.getInstance("AES");
    }
}
