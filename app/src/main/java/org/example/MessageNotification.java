package org.example;

public record MessageNotification(
        String nmsgNonce,
        String encryptedNMsgMeta
) {
}
