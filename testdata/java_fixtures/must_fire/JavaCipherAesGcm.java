package mustfire;

import javax.crypto.Cipher;

public class JavaCipherAesGcm {
    public Cipher aead() throws Exception {
        return Cipher.getInstance("AES/GCM/NoPadding");
    }
}
