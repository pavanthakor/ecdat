package mustfire;

import javax.crypto.KeyGenerator;

// A control: AES-256 is what CNSA 2.0 requires for long-lived data.
public class JavaKeygenAes256 {
    public KeyGenerator strong() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        return kg;
    }
}
