package client;

import java.security.SecureRandom;

public class Message {
    String message;
    byte[] nonce;

    public Message(String message) {
        this.message = message;
        this.nonce = new byte[24];
        new SecureRandom().nextBytes(this.nonce);
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public void setNonce(byte[] nonce) {
        this.nonce = nonce;
    }

    public String getMessage() {
        return message;
    }

    public byte[] getNonce() {
        return nonce;
    }
}
