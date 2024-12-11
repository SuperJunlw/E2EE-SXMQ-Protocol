package org.example;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

public class Commands {

    static final Charset CHARSET = StandardCharsets.US_ASCII;
    static final int BLOCK_SIZE = 16384;

    public static String queueURI(String serverIdentity,
                                  List<String> hostnames,
                                  String queueId,
                                  String versionRange,
                                  byte[] recipientDhPublicKey)
    {
        //create a string of the host names
        String hostNames = String.join(",", hostnames);

        //need to decode to get the string in order to read
        String keyBase64 = Base64.getEncoder().encodeToString(recipientDhPublicKey);

        //combine the parts to create the uri
        StringBuilder sb = new StringBuilder();
        sb.append("smp://")
                .append(serverIdentity)
                .append("@")
                .append(hostNames)
                .append("/")
                .append(queueId)
                .append("?v=")
                .append(versionRange)
                .append("&dh=")
                .append(keyBase64);

        return sb.toString();
    }

    //SMP COMMANDS
    public static String ping() {

        return "PING";
    }

    // Recipient Commands
    public static ByteBuffer create(byte[] recipientAuthPublicKey,
                                byte[] recipientDhPublicKey,
                                String basicAuth,
                                String subscribeMode,
                                String sndSecure) {
        ByteBuffer buffer = ByteBuffer.allocate(BLOCK_SIZE);

        buffer.put("NEW".getBytes(CHARSET));
        buffer.put(recipientAuthPublicKey);
        buffer.put(recipientDhPublicKey);
        buffer.put(basicAuth.getBytes(CHARSET));
        buffer.put(subscribeMode.getBytes(CHARSET));
        buffer.put(sndSecure.getBytes(CHARSET));
        buffer.flip();

        return buffer;
    }
    public static String subscribe(String queueId, byte[] signatureRecipientPrivateKey) {

        String keyBase64 = Base64.getEncoder().encodeToString(signatureRecipientPrivateKey);
        StringBuilder sb = new StringBuilder();
        //create the SUB command with the queueID and the signature of the recipient
        sb.append("SUB").append(queueId).append(keyBase64);
        return sb.toString();
    }

    public static String rcvSecure(String queueId, byte[] senderAuthPublicKey) {
        String keyBase64 = Base64.getEncoder().encodeToString(senderAuthPublicKey);
        StringBuilder sb = new StringBuilder();
        //create the Secure queue by recipient command with the queueID and sender's public key
        sb.append("SUB").append(queueId).append(keyBase64);
        return sb.toString();
    }

    //recipientNotificationDhPublicKey = length x509encoded
    //    the recipient's Curve25519 key for DH exchange to derive the secret
    //    that the server will use to encrypt notification metadata (encryptedNMsgMeta in NMSG)
    //    using [NaCl crypto_box][16] encryption scheme (curve25519xsalsa20poly1305).
    //notifierKey = length x509encoded
    //    the notifier's Ed25519 or X25519 public key to verify NSUB command for this queue
    public static String enableNotifications(String queueId, String notifierKey, byte[] recipientNotificationDhPublicKey) {
        String keyBase64 = Base64.getEncoder().encodeToString(recipientNotificationDhPublicKey);
        //create the Enable notifications command string to return
        StringBuilder sb = new StringBuilder();
        sb.append("NKEY")
                .append(queueId)
                .append(notifierKey)
                .append(keyBase64);

        return sb.toString();
    }
    
    public static String disableNotifications(String queueId) {

        return "NDEL"+queueId;
    }
    public static String getMessage(String queueId) {

        //The client MUST NOT use SUB and GET command
        // on the same queue in the same transport connection
        // - doing so would create an error.
        return "GET"+queueId;
    }

    //msgID to acknowledge a particular message -
    // to prevent double acknowledgement (e.g., when command response times out)
    // resulting in message being lost
    public static String acknowledge(String msgId) {
        if (msgId == null || msgId.isEmpty()) {
            throw new IllegalArgumentException("No Message ID is giving.");
        }
        return "ACK"+msgId;
    }

    //recipient can suspend a queue prior to deleting it to make sure that no messages are lost
    public static String suspend(String queueId) {

        return "OFF"+queueId; // TODO
    }

    //The recipient can delete the queue, whether it was suspended or not.
    //All undelivered messages must be deleted as soon as this command is received, before the response is sent.
    public static String delete(String queueId) {

        return "DEL" + queueId; // TODO
    }


    public static String getQueueInfo(String queueId) {
        // This command is used by the queue recipient to get the debugging
        // information about the current state of the queue.
        return "QUE" + queueId;
    }

    // Sender Commands


    //msgFlags - if the message includes a notification, should be "T" or "F"
    //smpEncMessage - The encrypted message, including either client message or confirmation.
    //This command is sent to the server by the sender both to confirm the queue after
    // the sender received out-of-band message from the recipient and to send messages
    // after the queue is secured
    public static String send(String msgFlags, String smpEncMessage) {
        StringBuilder sb = new StringBuilder();
        sb.append("SEND")
                .append(msgFlags)
                .append(smpEncMessage);
        return sb.toString();
    }

    //first message to be sent
    //This command is sent by the sender to the server to add sender's key to the queue
    //Once the queue is secured only authorized messages can be sent to it.
    public static String sndSecure(String queueId, byte[] senderAuthPublicKey) {
        String keyBase64 = Base64.getEncoder().encodeToString(senderAuthPublicKey);
        StringBuilder sb = new StringBuilder();
        sb.append("SKEY")
                .append(queueId)
                .append(keyBase64);
        return sb.toString();
    }

    // Proxy Commands

    //smpServer - The server address
    //basicAuth - Basic authentication "0" or "1password" server password.
    //The sender uses this command to request the session with the destination proxy.
    //Servers SHOULD support basic auth with this command, to allow only server owners
    // and trusted users to proxy commands to the destination servers.
    public static String proxySession(String smpServer, String basicAuth) {
        StringBuilder sb = new StringBuilder();
        sb.append("PRXY")
                .append(smpServer)
                .append(basicAuth);
        return sb.toString();
    }

    //encryptedTransmission - The encrypted and padded transmission
    //Sender can send SKEY and SEND commands via proxy after obtaining the session ID with PRXY command
    public static String proxyCommand(String smpVersion, String commandKey, String encryptedTransmission) {
        StringBuilder sb = new StringBuilder();
        sb.append("PFWD")
                .append(smpVersion)
                .append(commandKey)
                .append(encryptedTransmission);
        return sb.toString();
    }

    //forwardedTransmission = fwdCorrId fwdSmpVersion fwdCommandKey transmission
    //`fwdCorrId` - correlation ID used in `PFWD` command transmission - it is used as a nonce for client encryption,
    // and `fwdCorrId + 1` is used as a nonce for the destination server response encryption.
    //Having received PFWD command from the client, the server should additionally encrypt it
    // (without padding, as the received transmission is already encrypted by the client and padded
    // to a fixed size) together with the correlation ID, sender command key, and protocol version,
    // and forward it to the destination server as RFWD command:
    public static String relayCommand(String encryptedForwardedTransmission) {

        return "RFWD" + encryptedForwardedTransmission;
    }

    // Server Messages

    //If the queue is created successfully, the server must send queueIds response
    // with the recipient's and sender's queue IDs and public key to encrypt delivered message bodies
    public static QueueIdResponse queueIds(String recipientId, String senderId, byte[] srvDhPublicKey, String sndSecure) {
        QueueIdResponse response = new QueueIdResponse(
                recipientId,
                senderId,
                srvDhPublicKey,
                sndSecure
        );
        return response; // TODO
    }

    //When server delivers the messages to the recipient, message body
    // should be encrypted with the secret derived from DH exchange using
    // the keys passed during the queue creation and returned with queueIds response.
    //This is done to prevent the possibility of correlation of incoming and
    // outgoing traffic of SMP server inside transport protocol.
    //The server must deliver messages to all subscribed simplex queues
    // on the currently open transport connection. The syntax for the message delivery is
    public static QueueMessage message(String msgId, String encryptedRcvMsgBody) {
        QueueMessage msg = new QueueMessage(msgId, encryptedRcvMsgBody);

        return msg;
    }

    //The server will respond with notifierId response if notifications were enabled
    // and the notifier's key was successfully added to the queue
    //srvNotificationDhPublicKey - the server's Curve25519 key for DH exchange to derive the secret
    //that the server will use to encrypt notification metadata to the recipient
    public static NotifierId notifierId(String notifierId, byte[] srvNotificationDhPublicKey) {
        NotifierId id = new NotifierId(notifierId, srvNotificationDhPublicKey);
        return id;
    }

    //The server must deliver message notifications to all simplex queues that were
    // subscribed with subscribeNotifications command (NSUB) on the currently open transport connection
    //Message notification does not contain any message data or non E2E encrypted metadata.
    //encryptedNMsgMeta = <encrypted message metadata passed in notification>
    //nmsgNonce = <nonce used in NaCl crypto_box encryption scheme>
    public static MessageNotification messageNotification(String nmsgNonce, String encryptedNMsgMeta) {
        MessageNotification mn = new MessageNotification(nmsgNonce, encryptedNMsgMeta);
        return mn;
    }

    //When the client receives PKEY response it MUST validate that:
    //1. the fingerprint of the received certificate matches fingerprint in the server address
    // - it mitigates MITM attack by proxy.
    //2. the server session key is correctly signed with the received certificate.
    //certChain - The certificate chain
    //signedKey - key signed with certificate
    public static String proxySessionKey(String sessionId, String smpVersionRange, String certChain, byte[] signedKey) {
        String keyBase64 = Base64.getEncoder().encodeToString(signedKey);
        StringBuilder sb = new StringBuilder();
        sb.append("PKEY")
                .append(sessionId)
                .append(smpVersionRange)
                .append(certChain)
                .append(keyBase64);
        return sb.toString();
    }


    //encryptedTransmission - The encrypted and padded forwarded response
    //Having received the RRES response from the destination server,
    // proxy server will forward PRES response to the client. PRES response
    // should use the same correlation ID as PFWD command. The destination server
    // will use this correlation ID increased by 1 as a nonce for encryption of the response.
    public static String proxyResponse(String encryptedForwardedResponse) {
        return "PRES" + encryptedForwardedResponse;
    }

    //The destination server having received this command decrypts both encryption layers (proxy and client),
    // verifies client authorization as usual, processes it, and send the double encrypted RRES response to proxy.
    public static String relayResponse(String encryptedResponseTransmission) {
        return "RRES" + encryptedResponseTransmission;
    }

    //When another transport connection is subscribed to the same simplex queue,
    // the server should unsubscribe and to send the notification to the previously
    // subscribed transport connection
    public static String unsubscribed() {
        return "END";
    }

    //This command is used by the queue recipient to get the debugging information
    // about the current state of the queue.
    //The response to that command is INFO
    //Using the QueueInfo to create the queue info
    public static Object queueInfo(QueueInfo info) {
        return info.toString();
    }

    //When the command is successfully executed by the server, it should respond with OK response
    public static String ok() {
        return "OK";
    }

    public static String error(String errorType) {

        return "ERR" + errorType;
    }
}

