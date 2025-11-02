package security;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.security.MessageDigest; /**
 * Add HMAC for message integrity verification
 */
public class MessageIntegrity {
    private static final String HMAC_ALGORITHM = "HmacSHA256";

    public static byte[] generateHMAC(String message, SecretKey key)
            throws Exception {
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        mac.init(key);
        return mac.doFinal(message.getBytes("UTF-8"));
    }

    public static boolean verifyHMAC(String message, byte[] receivedHmac, SecretKey key)
            throws Exception {
        byte[] calculatedHmac = generateHMAC(message, key);
        return MessageDigest.isEqual(calculatedHmac, receivedHmac);
    }
}
