package mustfire;

import com.auth0.jwt.algorithms.Algorithm;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

// must_fire: java-hardcoded-key (ADR-0034) -- literals that REACH a key
// parameter. The sentinels must reach no Finding.
public class JavaKeyReachesSink {
    // High-entropy, key-ish AND reaching a sink: java-hardcoded-key-candidate
    // matches this field too, and the scanner folds it into the sink finding
    // -- one key, one finding.
    private static final String WEBHOOK_KEY = "f7ef507df605238c6f385a07dd5ee14f";

    public byte[] macOf(byte[] data) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(WEBHOOK_KEY.getBytes("UTF-8"), "HmacSHA256"));
        return mac.doFinal(data);
    }

    // Inline at the sink: auth0 java-jwt's HMAC secret.
    public Algorithm tokenAlgorithm() {
        return Algorithm.HMAC256("JAVASINKSENTINELinlineJwtSecret");
    }

    // Through getBytes() into a local, then the key spec.
    public SecretKeySpec archiveKey() {
        byte[] keyBytes = "JAVASINKSENTINELarchiveAesKey01".getBytes();
        return new SecretKeySpec(keyBytes, "AES");
    }
}
