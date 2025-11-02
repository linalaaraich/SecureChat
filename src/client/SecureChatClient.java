package client;

import common.CryptoUtils;
import common.CryptoUtils.EncryptedMessage;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Base64;
import java.util.Scanner;

public class SecureChatClient {
    private Socket socket;
    private BufferedReader reader;
    private PrintWriter writer;
    private KeyPair clientKeyPair;
    private PublicKey serverPublicKey;
    private SecretKey sessionKey;
    private String username;
    private volatile boolean running = true;

    public SecureChatClient(String serverHost, int serverPort) throws Exception {
        // Generate client's RSA keypair
        this.clientKeyPair = CryptoUtils.generateRSAKeyPair();
        System.out.println("[CLIENT] RSA KeyPair generated");

        // Connect to server
        this.socket = new Socket(serverHost, serverPort);
        this.reader = new BufferedReader(
                new InputStreamReader(socket.getInputStream(), "UTF-8"));
        this.writer = new PrintWriter(
                new OutputStreamWriter(socket.getOutputStream(), "UTF-8"), true);

        System.out.println("[CLIENT] Connected to server: " + serverHost + ":" + serverPort);
    }

    /**
     * Perform secure handshake with server
     */
    private void performHandshake() throws Exception {
        // Step 1: Receive server's public key
        String serverKeyLine = reader.readLine();
        if (serverKeyLine.startsWith("SERVER_PUBLIC_KEY:")) {
            String serverPubKeyStr = serverKeyLine.substring(18);
            serverPublicKey = CryptoUtils.stringToPublicKey(serverPubKeyStr);
            System.out.println("[CLIENT] Received server public key");
        }

        // Step 2: Send client's public key
        String clientPubKeyStr = CryptoUtils.publicKeyToString(
                clientKeyPair.getPublic());
        writer.println("CLIENT_PUBLIC_KEY:" + clientPubKeyStr);
        System.out.println("[CLIENT] Sent client public key");

        // Step 3: Receive encrypted session key
        String sessionKeyLine = reader.readLine();
        if (sessionKeyLine.startsWith("SESSION_KEY:")) {
            String encSessionKeyStr = sessionKeyLine.substring(12);
            byte[] encryptedSessionKey = Base64.getDecoder().decode(encSessionKeyStr);

            // Decrypt session key using client's private key
            byte[] sessionKeyBytes = CryptoUtils.decryptRSA(
                    encryptedSessionKey, clientKeyPair.getPrivate());
            sessionKey = new SecretKeySpec(sessionKeyBytes, "AES");


            System.out.println("[CLIENT] Session key received and decrypted");
            System.out.println("[CLIENT] Secure channel established!");
        }
    }

    /**
     * Start the client - perform handshake and begin messaging
     */
    public void start() throws Exception {
        // Perform secure handshake
        performHandshake();

        // Get username
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter your username: ");
        username = scanner.nextLine();
        writer.println("USERNAME:" + username);

        // Start message listener thread
        Thread listenerThread = new Thread(new MessageListener());
        listenerThread.start();

        // Main loop - send messages
        System.out.println("\n=== SecureChat Started ===");
        System.out.println("Type your messages below (type /quit to exit):\n");

        while (running) {
            String message = scanner.nextLine();

            if (message.equalsIgnoreCase("/quit")) {
                running = false;
                break;
            }

            if (!message.trim().isEmpty()) {
                sendEncryptedMessage(message);
            }
        }

        disconnect();
    }

    /**
     * Send encrypted message to server
     */
    private void sendEncryptedMessage(String message) throws Exception {
        // Encrypt message with session key
        EncryptedMessage encryptedMsg = CryptoUtils.encryptAES(message, sessionKey);
        writer.println("MESSAGE:" + encryptedMsg.toBase64());
    }

    /**
     * MessageListener - Handles incoming messages from server
     */
    private class MessageListener implements Runnable {
        @Override
        public void run() {
            try {
                String line;
                while (running && (line = reader.readLine()) != null) {
                    if (line.startsWith("MESSAGE:")) {
                        // Decrypt and display message
                        String encData = line.substring(8);
                        EncryptedMessage encMsg = EncryptedMessage.fromBase64(encData);
                        String plaintext = CryptoUtils.decryptAES(encMsg, sessionKey);
                        System.out.println(plaintext);

                    } else if (line.startsWith("SYSTEM:")) {
                        // System messages (join/leave notifications)
                        System.out.println("[" + line.substring(7) + "]");

                    } else if (line.startsWith("ERROR:")) {
                        System.err.println("[ERROR] " + line.substring(6));
                        running = false;
                    }
                }
            } catch (Exception e) {
                if (running) {
                    System.err.println("[CLIENT] Error receiving message: " + e.getMessage());
                }
            }
        }
    }

    private void disconnect() {
        try {
            running = false;
            socket.close();
            System.out.println("\n[CLIENT] Disconnected from server");
        } catch (IOException e) {
            System.err.println("[CLIENT] Error during disconnect: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        if (args.length != 2) {
            System.out.println("Usage: java SecureChatClient <server_host> <server_port>");
            System.out.println("Example: java SecureChatClient localhost 8888");
            return;
        }

        try {
            String host = args[0];
            int port = Integer.parseInt(args[1]);

            SecureChatClient client = new SecureChatClient(host, port);
            client.start();

        } catch (Exception e) {
            System.err.println("[CLIENT] Fatal error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}