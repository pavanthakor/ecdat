package mustfire;

import javax.crypto.Cipher;

public class JavaCipherDes {
    public Cipher legacy() throws Exception {
        return Cipher.getInstance("DES/CBC/PKCS5Padding");
    }
}
