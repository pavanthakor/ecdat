package mustfire;

import javax.crypto.KeyGenerator;

public class JavaKeygenAes128 {
    public KeyGenerator weak() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
        return kg;
    }
}
