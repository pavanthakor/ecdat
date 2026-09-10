package mustfire;

import javax.crypto.Cipher;

public class JavaCipherRc4 {
    public Cipher stream() throws Exception {
        return Cipher.getInstance("RC4");
    }
}
