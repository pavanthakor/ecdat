package mustfire;

import javax.crypto.spec.SecretKeySpec;

// must_fire: java-hardcoded-key-der (ADR-0034) -- a base64 DER structure is key
// material by its SHAPE alone. `MII` is a DER SEQUENCE with a two-byte length
// (X.690 s8.1.3), the header of every RSA key and every X.509 certificate
// (RFC 8017, RFC 5280). The body is filler; the sentinel must reach no Finding.
public class JavaDerKey {
    private static final String PARTNER_KEY_DER =
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAJAVADERSENTINELnotARealKeyJustFillerForTheShapeOnly0123456789";

    // It reaches a key parameter too. The DER rule owns a shaped literal, so
    // this is still ONE finding -- not a DER finding plus a sink finding.
    public SecretKeySpec partnerKey() {
        return new SecretKeySpec(PARTNER_KEY_DER.getBytes(), "HmacSHA256");
    }
}
