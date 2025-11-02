package security;

import common.CryptoUtils;
import server.SecureChatServer;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.*;
import java.util.concurrent.*;

/**
 * Secure key storage using Java KeyStore
 */
public class KeyStoreManager {
    private static final String KEYSTORE_TYPE = "PKCS12";
    private static final String KEYSTORE_FILE = "securechat.p12";

    public static void saveKeyPair(KeyPair keyPair, String alias, char[] password)
            throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);

        // Load existing or create new keystore
        File keystoreFile = new File(KEYSTORE_FILE);
        if (keystoreFile.exists()) {
            try (FileInputStream fis = new FileInputStream(keystoreFile)) {
                keyStore.load(fis, password);
            }
        } else {
            keyStore.load(null, password);
        }

        // Store the key pair
        X509Certificate[] chain = new X509Certificate[1];
        chain[0] = generateSelfSignedCertificate(keyPair);

        keyStore.setKeyEntry(alias, keyPair.getPrivate(), password, chain);

        // Save keystore
        try (FileOutputStream fos = new FileOutputStream(keystoreFile)) {
            keyStore.store(fos, password);
        }
    }

    public static KeyPair loadKeyPair(String alias, char[] password)
            throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);

        try (FileInputStream fis = new FileInputStream(KEYSTORE_FILE)) {
            keyStore.load(fis, password);
        }

        PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password);
        Certificate cert = keyStore.getCertificate(alias);
        PublicKey publicKey = cert.getPublicKey();

        return new KeyPair(publicKey, privateKey);
    }

    private static X509Certificate generateSelfSignedCertificate(KeyPair keyPair) throws Exception {
        // Simplified: generate a fake placeholder certificate (not real)
        // Just return a dummy in-memory X509Certificate for KeyStore storage
        return new X509Certificate() {
            @Override public void checkValidity() {}
            @Override public void checkValidity(java.util.Date date) {}
            @Override public int getVersion() { return 3; }
            @Override public java.math.BigInteger getSerialNumber() { return java.math.BigInteger.ONE; }
            @Override public java.security.Principal getIssuerDN() { return () -> "CN=SecureChatDummy"; }
            @Override public java.security.Principal getSubjectDN() { return () -> "CN=SecureChatDummy"; }
            @Override public java.util.Date getNotBefore() { return new java.util.Date(); }
            @Override public java.util.Date getNotAfter() { return new java.util.Date(System.currentTimeMillis() + 86400000L); }
            @Override public byte[] getTBSCertificate() { return new byte[0]; }
            @Override public byte[] getSignature() { return new byte[0]; }
            @Override public String getSigAlgName() { return "NONE"; }
            @Override public String getSigAlgOID() { return "1.2.3.4"; }
            @Override public byte[] getSigAlgParams() { return new byte[0]; }
            @Override public boolean[] getIssuerUniqueID() { return null; }
            @Override public boolean[] getSubjectUniqueID() { return null; }
            @Override public boolean[] getKeyUsage() { return null; }
            @Override public int getBasicConstraints() { return -1; }
            @Override public byte[] getEncoded() { return new byte[0]; }
            @Override public void verify(java.security.PublicKey key) {}
            @Override public void verify(java.security.PublicKey key, String sigProvider) {}
            @Override public String toString() { return "Dummy X509 Certificate"; }
            @Override public java.security.PublicKey getPublicKey() { return keyPair.getPublic(); }
            @Override public Set<String> getCriticalExtensionOIDs() { return null; }
            @Override public Set<String> getNonCriticalExtensionOIDs() { return null; }
            @Override public byte[] getExtensionValue(String oid) { return null; }
            @Override public boolean hasUnsupportedCriticalExtension() { return false; }
        };
    }

}


