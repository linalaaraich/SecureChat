package common;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class CryptoUtils {
    // Use GCM mode for authenticated encryption
    private static final String AES_ALGORITHM = "AES/GCM/NoPadding";
    private static final String RSA_ALGORITHM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final int GCM_TAG_LENGTH = 128;
    private static final int GCM_IV_LENGTH = 12;
    private static final int RSA_KEY_SIZE = 4096;
    private static final int AES_KEY_SIZE = 256;

    /**
     * Generate RSA KeyPair for asymmetric encryption
     * Used for initial secure key exchange
     */
    public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        SecureRandom secureRandom = SecureRandom.getInstanceStrong();
        keyGen.initialize(RSA_KEY_SIZE, secureRandom);
        return keyGen.generateKeyPair();
    }

    /**
     * Generate AES Session Key for symmetric encryption
     * This key will be shared among all participants
     */
    public static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        SecureRandom secureRandom = SecureRandom.getInstanceStrong();
        keyGen.init(AES_KEY_SIZE, secureRandom);
        return keyGen.generateKey();
    }

    /**
     * Encrypt data using RSA public key
     * Used to securely transmit AES session key
     */
    public static byte[] encryptRSA(byte[] data, PublicKey publicKey)
            throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    /**
     * Decrypt data using RSA private key
     * Used to receive AES session key
     */
    public static byte[] decryptRSA(byte[] encryptedData, PrivateKey privateKey)
            throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedData);
    }

    /**
     * Encrypt message using AES-GCM (Authenticated Encryption)
     * GCM mode provides both confidentiality and authenticity
     */
    public static EncryptedMessage encryptAES(String plaintext, SecretKey key)
            throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);

        // Generate random IV for each message
        byte[] iv = new byte[GCM_IV_LENGTH];
        SecureRandom.getInstanceStrong().nextBytes(iv);

        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);

        byte[] ciphertext = cipher.doFinal(plaintext.getBytes("UTF-8"));

        return new EncryptedMessage(ciphertext, iv);
    }

    /**
     * Decrypt message using AES-GCM
     * Verifies authenticity while decrypting
     */
    public static String decryptAES(EncryptedMessage encMsg, SecretKey key)
            throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM);

        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, encMsg.getIv());
        cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);

        byte[] plaintext = cipher.doFinal(encMsg.getCiphertext());
        return new String(plaintext, "UTF-8");
    }

    /**
     * Convert PublicKey to Base64 String for transmission
     */
    public static String publicKeyToString(PublicKey publicKey) {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    /**
     * Convert Base64 String back to PublicKey
     */
    public static PublicKey stringToPublicKey(String keyString)
            throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(keyString);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }

    /**
     * Helper class to bundle encrypted data with IV
     */
    public static class EncryptedMessage {
        private final byte[] ciphertext;
        private final byte[] iv;

        public EncryptedMessage(byte[] ciphertext, byte[] iv) {
            this.ciphertext = ciphertext;
            this.iv = iv;
        }

        public byte[] getCiphertext() { return ciphertext; }
        public byte[] getIv() { return iv; }

        // Convert to Base64 for network transmission
        public String toBase64() {
            String ctBase64 = Base64.getEncoder().encodeToString(ciphertext);
            String ivBase64 = Base64.getEncoder().encodeToString(iv);
            return ivBase64 + ":" + ctBase64;
        }

        // Reconstruct from Base64
        public static EncryptedMessage fromBase64(String base64) {
            String[] parts = base64.split(":");
            byte[] iv = Base64.getDecoder().decode(parts[0]);
            byte[] ciphertext = Base64.getDecoder().decode(parts[1]);
            return new EncryptedMessage(ciphertext, iv);
        }
    }
}