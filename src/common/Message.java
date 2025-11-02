package common;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class Message implements Serializable {
    private static final long serialVersionUID = 1L;

    public enum MessageType {
        TEXT,           // Regular text message
        HANDSHAKE,      // Key exchange messages
        SYSTEM,         // System notifications
        FILE,           // File transfer (future enhancement)
        KEY_ROTATION    // Session key rotation
    }

    private String sender;
    private String content;
    private MessageType type;
    private LocalDateTime timestamp;
    private byte[] signature;  // Digital signature for message integrity

    public Message(String sender, String content, MessageType type) {
        this.sender = sender;
        this.content = content;
        this.type = type;
        this.timestamp = LocalDateTime.now();
    }

    // Getters and setters
    public String getSender() { return sender; }
    public String getContent() { return content; }
    public MessageType getType() { return type; }
    public LocalDateTime getTimestamp() { return timestamp; }
    public byte[] getSignature() { return signature; }
    public void setSignature(byte[] signature) { this.signature = signature; }

    public String getFormattedTimestamp() {
        return timestamp.format(DateTimeFormatter.ofPattern("HH:mm:ss"));
    }

    @Override
    public String toString() {
        return String.format("[%s] %s: %s",
                getFormattedTimestamp(), sender, content);
    }
}