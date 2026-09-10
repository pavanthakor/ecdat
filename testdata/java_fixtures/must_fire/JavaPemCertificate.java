package mustfire;

public class JavaPemCertificate {
    // An embedded certificate. The sentinel in the body must reach no Finding.
    private static final String PARTNER_CERT =
        "-----BEGIN CERTIFICATE-----\n"
        + "JAVANOTAREALCERTJAVANOTAREALCERTJAVANOTAREALCERTJAVANOTAREALCERT\n"
        + "-----END CERTIFICATE-----";

    public String cert() {
        return PARTNER_CERT;
    }
}
