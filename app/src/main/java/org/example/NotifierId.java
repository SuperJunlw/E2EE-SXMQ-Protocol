package org.example;

public record NotifierId(
        String notifierId,
        byte[] srvNotificationDhPublicKey
) {
}
