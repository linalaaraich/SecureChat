package security;

import common.CryptoUtils;
import server.SecureChatServer;

import javax.crypto.SecretKey;
import java.util.Timer;
import java.util.TimerTask; /**
 * Implement key rotation for perfect forward secrecy
 */
public class KeyRotationManager {
    private static final long KEY_ROTATION_INTERVAL = 3600000; // 1 hour
    private Timer rotationTimer;

    public void startKeyRotation(SecureChatServer server) {
        rotationTimer = new Timer(true);
        rotationTimer.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                try {
                    // Generate new session key
                    SecretKey newSessionKey = CryptoUtils.generateAESKey();

                    // Distribute to all connected clients
                    server.distributeNewSessionKey(newSessionKey);

                    System.out.println("[SECURITY] Session key rotated");
                } catch (Exception e) {
                    System.err.println("[SECURITY] Key rotation failed: " + e.getMessage());
                }
            }
        }, KEY_ROTATION_INTERVAL, KEY_ROTATION_INTERVAL);
    }
}
