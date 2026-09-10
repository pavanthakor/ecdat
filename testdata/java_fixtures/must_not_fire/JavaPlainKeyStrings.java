// must_not_fire (ADR-0034): the Juice Shop false-positive class, in Java.
// Every name reads like a key; every value is a cookie name, header name,
// property key or cache key. Nothing may fire.
package mustnotfire;

import java.util.HashMap;
import java.util.Map;

public class JavaPlainKeyStrings {
    private static final String SESSION_COOKIE_KEY = "JSESSIONID";
    private static final String API_KEY_HEADER = "X-Api-Key";
    private static final String SECRET_KEY_PROPERTY = "app.security.secret-key";
    private static final String PASSWORD_PARAM = "password";
    private final String cacheKey = "basket-42";

    public Map<String, String> headers(String apiKey) {
        Map<String, String> headers = new HashMap<>();
        headers.put(API_KEY_HEADER, apiKey);
        headers.put("Cookie", SESSION_COOKIE_KEY + "=" + cacheKey);
        return headers;
    }

    public String property() {
        return System.getProperty(SECRET_KEY_PROPERTY, PASSWORD_PARAM);
    }
}
