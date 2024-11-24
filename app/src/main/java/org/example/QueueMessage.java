package org.example;

public record QueueMessage(
        String msgId,
        String encryptedRcvMsgBody
) {
}
