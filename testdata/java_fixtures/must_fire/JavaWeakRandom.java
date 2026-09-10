package mustfire;

import java.util.Random;

public class JavaWeakRandom {
    // java.util.Random is a 48-bit LCG. Using it for a token is a
    // key-recovery bug, not a style problem.
    public long newSessionToken() {
        Random rng = new Random();
        long token = rng.nextLong();
        return token;
    }
}
