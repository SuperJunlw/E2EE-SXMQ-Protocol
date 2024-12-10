package org.example;

public record QueueIdResponse(
        String recipientId,
        String senderId,
        byte[] srvDhPublicKey,
        String sndSecure
) {
    // Additional methods can be added if needed
}
