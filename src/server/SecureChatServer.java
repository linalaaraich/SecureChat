package server;


import common.CryptoUtils;
import common.CryptoUtils.EncryptedMessage;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;

public class SecureChatServer {
    private static final int PORT = 8888;
    private ServerSocket serverSocket;
    private KeyPair serverKeyPair;
    private SecretKey sessionKey;
    private final Map<String, ClientHandler> clients = new ConcurrentHashMap<>();
    private final ExecutorService executor = Executors.newCachedThreadPool();

    public SecureChatServer() throws Exception {
        // Initialize server's RSA keypair
        this.serverKeyPair = CryptoUtils.generateRSAKeyPair();
        // Generate AES session key for all clients
        this.sessionKey = CryptoUtils.generateAESKey();

        System.out.println("[SERVER] RSA KeyPair generated (4096-bit)");
        System.out.println("[SERVER] AES Session Key generated (256-bit)");
    }

    public void start() throws IOException {
        serverSocket = new ServerSocket(PORT);
        System.out.println("[SERVER] Server started on port " + PORT);

        // Accept client connections
        while (!serverSocket.isClosed()) {
            try {
                Socket clientSocket = serverSocket.accept();
                System.out.println("[SERVER] New client connected: " +
                        clientSocket.getInetAddress());

                // Handle each client in a separate thread
                ClientHandler handler = new ClientHandler(clientSocket);
                executor.execute(handler);

            } catch (IOException e) {
                if (!serverSocket.isClosed()) {
                    System.err.println("[SERVER] Error accepting connection: " + e.getMessage());
                }
            }
        }
    }

    /**
     * Broadcast encrypted message to all clients except sender
     */
    private void broadcastMessage(String message, String senderUsername) {
        for (Map.Entry<String, ClientHandler> entry : clients.entrySet()) {
            if (!entry.getKey().equals(senderUsername)) {
                try {
                    entry.getValue().sendMessage(message);
                } catch (Exception e) {
                    System.err.println("[SERVER] Failed to send to " + entry.getKey());
                }
            }
        }
    }

    /**
     * ClientHandler - Manages individual client connections
     */
    private class ClientHandler implements Runnable {
        private Socket socket;
        private BufferedReader reader;
        private PrintWriter writer;
        private String username;
        private PublicKey clientPublicKey;

        public ClientHandler(Socket socket) throws IOException {
            this.socket = socket;
            this.reader = new BufferedReader(
                    new InputStreamReader(socket.getInputStream(), "UTF-8"));
            this.writer = new PrintWriter(
                    new OutputStreamWriter(socket.getOutputStream(), "UTF-8"), true);
        }

        @Override
        public void run() {
            try {
                // Phase 1: Send server's public key
                String serverPubKeyStr = CryptoUtils.publicKeyToString(
                        serverKeyPair.getPublic());
                writer.println("SERVER_PUBLIC_KEY:" + serverPubKeyStr);

                // Phase 2: Receive client's public key
                String clientKeyLine = reader.readLine();
                if (clientKeyLine.startsWith("CLIENT_PUBLIC_KEY:")) {
                    String clientPubKeyStr = clientKeyLine.substring(18);
                    clientPublicKey = CryptoUtils.stringToPublicKey(clientPubKeyStr);
                    System.out.println("[SERVER] Received client public key");
                }

                // Phase 3: Send encrypted session key
                byte[] encryptedSessionKey = CryptoUtils.encryptRSA(
                        sessionKey.getEncoded(), clientPublicKey);
                String encSessionKeyStr = Base64.getEncoder().encodeToString(
                        encryptedSessionKey);
                writer.println("SESSION_KEY:" + encSessionKeyStr);

                // Phase 4: Receive and validate username
                String usernameLine = reader.readLine();
                if (usernameLine.startsWith("USERNAME:")) {
                    username = usernameLine.substring(9);

                    // Check for duplicate username
                    if (clients.containsKey(username)) {
                        writer.println("ERROR:Username already taken");
                        socket.close();
                        return;
                    }

                    clients.put(username, this);
                    System.out.println("[SERVER] User " + username + " registered");

                    // Notify all clients
                    broadcastMessage("SYSTEM:" + username + " joined the chat", "SYSTEM");
                }

                // Phase 5: Handle encrypted messages
                String encryptedMessage;
                while ((encryptedMessage = reader.readLine()) != null) {
                    if (encryptedMessage.startsWith("MESSAGE:")) {
                        String encData = encryptedMessage.substring(8);

                        // Decrypt message
                        EncryptedMessage encMsg = EncryptedMessage.fromBase64(encData);
                        String plaintext = CryptoUtils.decryptAES(encMsg, sessionKey);

                        System.out.println("[SERVER] Message from " + username + ": " + plaintext);

                        // Re-encrypt and broadcast to other clients
                        String broadcastMsg = username + ": " + plaintext;
                        EncryptedMessage reEncrypted = CryptoUtils.encryptAES(
                                broadcastMsg, sessionKey);
                        broadcastMessage("MESSAGE:" + reEncrypted.toBase64(), username);
                    }
                }

            } catch (Exception e) {
                System.err.println("[SERVER] Error handling client " + username + ": " +
                        e.getMessage());
            } finally {
                disconnect();
            }
        }

        private void sendMessage(String message) throws Exception {
            writer.println(message);
        }

        private void disconnect() {
            try {
                if (username != null) {
                    clients.remove(username);
                    broadcastMessage("SYSTEM:" + username + " left the chat", "SYSTEM");
                }
                socket.close();
            } catch (IOException e) {
                System.err.println("[SERVER] Error closing connection: " + e.getMessage());
            }
        }
    }

    public void distributeNewSessionKey(SecretKey newKey) {
        try {
            this.sessionKey = newKey; // Update server’s session key

            // Encrypt and send the new key to every connected client
            for (Map.Entry<String, ClientHandler> entry : clients.entrySet()) {
                ClientHandler handler = entry.getValue();
                try {
                    byte[] encryptedSessionKey = CryptoUtils.encryptRSA(
                            newKey.getEncoded(),
                            handler.clientPublicKey
                    );
                    String encSessionKeyStr = Base64.getEncoder().encodeToString(encryptedSessionKey);
                    handler.sendMessage("SESSION_KEY:" + encSessionKeyStr);
                } catch (Exception e) {
                    System.err.println("[SERVER] Failed to send new session key to " + entry.getKey());
                }
            }
        } catch (Exception e) {
            System.err.println("[SERVER] Error distributing new session key: " + e.getMessage());
        }
    }


    public static void main(String[] args) {
        try {
            SecureChatServer server = new SecureChatServer();
            server.start();
        } catch (Exception e) {
            System.err.println("[SERVER] Fatal error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}