package mustfire;

import java.security.KeyPairGenerator;
import java.security.KeyPair;

public class JavaRsaKeygen {
    public KeyPair newTransportKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }
}
