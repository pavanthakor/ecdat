package mustfire;

import javax.crypto.Cipher;

public class JavaCipherDesede {
    public Cipher legacy() throws Exception {
        return Cipher.getInstance("DESede/CBC/PKCS5Padding");
    }
}
