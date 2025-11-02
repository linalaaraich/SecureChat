package security;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;

public class NonceManager {
    private final Set<String> usedNonces = Collections.synchronizedSet(
            new HashSet<>());
    private final long NONCE_LIFETIME = 300000; // 5 minutes

    public String generateNonce() {
        byte[] nonceBytes = new byte[16];
        try {
            SecureRandom.getInstanceStrong().nextBytes(nonceBytes);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        String nonce = Base64.getEncoder().encodeToString(nonceBytes);

        usedNonces.add(nonce);

        // Clean up old nonces after lifetime
        Timer cleanupTimer = new Timer(true);
        cleanupTimer.schedule(new TimerTask() {
            @Override
            public void run() {
                usedNonces.remove(nonce);
            }
        }, NONCE_LIFETIME);

        return nonce;
    }

    public boolean validateNonce(String nonce) {
        return usedNonces.remove(nonce); // Returns true if nonce was present
    }
}
