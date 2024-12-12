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

    //TRANSPORT PRIMITIVES

    /**
     * Used to generate a transport block. A single transport block can contain multiple transmissions, with each
     * transmission containing a single SXMQ command.
     * @param transmissions An individual transmission. Generate using the transmission() function
     * @return A new transport block.
     */
    public static ByteBuffer transportBlock(List<ByteBuffer> transmissions) {
        ByteBuffer transportBlock = ByteBuffer.allocate(BLOCK_SIZE);

        byte transmissionCount = (byte) transmissions.size();
        transportBlock.put(transmissionCount);
        transmissions.forEach(transportBlock::put);
        return transportBlock;
    }

    /**
     * Used to create a transmission.
     * @param authorization A shortString. Is empty with the PING command or in server responses. Used with the SEND command.
     * @param sessionId A shortString. The session identifier returned from the server hello response.
     * @param corrId See corrId()
     * @param entityId A shortString. queueId or proxySessionId
     * @param smpCommand The actual sxmq command. See the SMP COMMANDS section.
     * @return A new transmission.
     */
    public static ByteBuffer transmission(
            ByteBuffer authorization, // shortString, empty with PING command
            ByteBuffer sessionId,
            ByteBuffer corrId,
            ByteBuffer entityId, // shortString queueId or proxySessionId
            ByteBuffer smpCommand
    ) {
        ByteBuffer transmission = ByteBuffer.allocate(BLOCK_SIZE);
        transmission.put(authorization);
        transmission.put(sessionId);
        transmission.put(corrId);
        transmission.put(entityId);
        transmission.put(smpCommand);
        return transmission.flip();
    }

    /**
     * Used to generate a shortString from an array of bytes. Simply returns an array containing the original array's
     * length followed by the original array.
     * @param string An array of bytes to turn into a shortString.
     * @return A new shortString.
     */
    public static ByteBuffer shortString(byte[] string) {
        ByteBuffer shortString = ByteBuffer.allocate(string.length + 1);
        shortString.put((byte) string.length);
        shortString.put(string);
        return shortString.flip();
    }

    /**
     * Generate a shortString for an empty array. Simply returns an array containing the byte 0x00.
     * @return an empty shortString
     */
    public static ByteBuffer emptyShortString() {
        ByteBuffer emptyShortString = ByteBuffer.allocate(1);
        emptyShortString.put((byte) 0);
        return emptyShortString.flip();
    }

    /**
     * Creates a new corrId object. It takes a byte array of length 24 and returns a new array containing the  byte
     * 0x18 followed by the original array
     * @param randomCorrelationId A byte array of length 24
     * @return A new corrId
     */
    public static ByteBuffer corrId(byte[] randomCorrelationId) {
        if (randomCorrelationId.length != 24) {
            throw new RuntimeException("randomCorrelationId must have a length of 24");
        }
        ByteBuffer corrId = ByteBuffer.allocate(25);
        corrId.put((byte) 0x18); // indicates that a randomCorrelationId is present
        corrId.put(randomCorrelationId);
        return corrId.flip();
    }

    /**
     * Generates a client hello request containing the chosen SXMQ protocol version.
     * @param protocolVersion The chosen protocol version
     * @return a client hello request
     */
    public static ByteBuffer clientHello(short protocolVersion) {
        ByteBuffer b = ByteBuffer.allocate(2);
        b.putShort(protocolVersion);
        return b.flip();
    }

    /**
     * Pads either a transportBlock or a clientHello to a length of 16384
     * @param message a transportBlock or a clientHello
     * @return A padded transportBlock or a padded clientHello. This can then be sent to the SXMQ server.
     */
    public static byte[] paddedString(ByteBuffer message) {
        byte padSymbol = (byte)'#';
        if (message.remaining() >= BLOCK_SIZE) {
            throw new RuntimeException("Message must be less than " + BLOCK_SIZE + " bytes long. Currently it is " +
                    message.remaining() + " bytes long.");
        }
        short originalLength = (short) message.remaining();
        ByteBuffer paddedString = ByteBuffer.allocate(BLOCK_SIZE);
        // add the block size to the beginning of the paddedString
        paddedString.putShort(originalLength);
        // add the message immediately after
        paddedString.put(message);
        // fill the remainder of the buffer with '#'
        while(paddedString.hasRemaining()) {
            paddedString.put(padSymbol);
        }
        return paddedString.array();
    }

    //SMP COMMANDS
    public static ByteBuffer ping() {
        return ByteBuffer.wrap("PING".getBytes(CHARSET));
    }

    // Recipient Commands
    public static ByteBuffer create(byte[] recipientAuthPublicKey,
                                byte[] recipientDhPublicKey,
                                String basicAuth,
                                String subscribeMode,
                                String sndSecure) {
        ByteBuffer buffer = ByteBuffer.allocate(BLOCK_SIZE);

        buffer.put("NEW ".getBytes(CHARSET));
        buffer.put(recipientAuthPublicKey);
        buffer.put(recipientDhPublicKey);
        buffer.put(basicAuth.getBytes(CHARSET));
        buffer.put(subscribeMode.getBytes(CHARSET));
        buffer.put(sndSecure.getBytes(CHARSET));
        //buffer.putShort((short) 35);
        buffer.flip();

        return buffer;
    }
    public static ByteBuffer subscribe() {

        //create the SUB command
        ByteBuffer buffer = ByteBuffer.allocate(BLOCK_SIZE);
        buffer.put("SUB".getBytes(CHARSET));
        buffer.flip();

        return buffer;
    }

    public static ByteBuffer rcvSecure(byte[] senderAuthPublicKey) {

        //create the Secure queue by recipient command with sender's public key
        ByteBuffer buffer = ByteBuffer.allocate(BLOCK_SIZE);
        buffer.put("KEY ".getBytes(CHARSET));
        buffer.put(senderAuthPublicKey);
        buffer.flip();

        return buffer;
    }

    //recipientNotificationDhPublicKey = length x509encoded
    //    the recipient's Curve25519 key for DH exchange to derive the secret
    //    that the server will use to encrypt notification metadata (encryptedNMsgMeta in NMSG)
    //    using [NaCl crypto_box][16] encryption scheme (curve25519xsalsa20poly1305).
    //notifierKey = length x509encoded
    //    the notifier's Ed25519 or X25519 public key to verify NSUB command for this queue
    public static ByteBuffer enableNotifications(byte[] notifierPublicKey, byte[] recipientNotificationDhPublicKey) {

        //create the Enable notifications command string to return
        ByteBuffer buffer = ByteBuffer.allocate(BLOCK_SIZE);
        buffer.put("NKEY ".getBytes(CHARSET));
        buffer.put(notifierPublicKey);
        buffer.put(recipientNotificationDhPublicKey);
        buffer.flip();

        return buffer;
    }
    
    public static ByteBuffer disableNotifications() {

        ByteBuffer buffer = ByteBuffer.allocate(BLOCK_SIZE);
        buffer.put("NDEL".getBytes(CHARSET));
        buffer.flip();

        return buffer;
    }
    public static ByteBuffer getMessage() {

        //The client MUST NOT use SUB and GET command
        // on the same queue in the same transport connection
        // - doing so would create an error.
        ByteBuffer buffer = ByteBuffer.allocate(BLOCK_SIZE);
        buffer.put("GET".getBytes(CHARSET));
        buffer.flip();

        return buffer;
    }

    //msgID to acknowledge a particular message -
    // to prevent double acknowledgement (e.g., when command response times out)
    // resulting in message being lost
    public static ByteBuffer acknowledge(String msgId) {

        ByteBuffer buffer = ByteBuffer.allocate(BLOCK_SIZE);
        buffer.put("ACK".getBytes(CHARSET));
        buffer.put(msgId.getBytes(CHARSET));
        buffer.flip();

        return buffer;
    }

    //recipient can suspend a queue prior to deleting it to make sure that no messages are lost
    public static ByteBuffer suspend() {

        ByteBuffer buffer = ByteBuffer.allocate(BLOCK_SIZE);
        buffer.put("OFF".getBytes(CHARSET));
        buffer.flip();

        return buffer;
    }

    //The recipient can delete the queue, whether it was suspended or not.
    //All undelivered messages must be deleted as soon as this command is received, before the response is sent.
    public static ByteBuffer delete() {

        ByteBuffer buffer = ByteBuffer.allocate(BLOCK_SIZE);
        buffer.put("DEL".getBytes(CHARSET));
        buffer.flip();

        return buffer;
    }


    public static ByteBuffer getQueueInfo() {
        // This command is used by the queue recipient to get the debugging
        // information about the current state of the queue.
        ByteBuffer buffer = ByteBuffer.allocate(BLOCK_SIZE);
        buffer.put("QUE".getBytes(CHARSET));
        buffer.flip();

        return buffer;
    }

    // Sender Commands


    //msgFlags - if the message includes a notification, should be "T" or "F"
    //smpEncMessage - The encrypted message, including either client message or confirmation.
    //This command is sent to the server by the sender both to confirm the queue after
    // the sender received out-of-band message from the recipient and to send messages
    // after the queue is secured
    public static ByteBuffer send(String msgFlags, byte[] smpEncMessage) {
        ByteBuffer buffer = ByteBuffer.allocate(BLOCK_SIZE);
        buffer.put("SEND ".getBytes(CHARSET));
        buffer.put(msgFlags.getBytes(CHARSET));
        buffer.put(smpEncMessage);
        buffer.flip();

        return buffer;
    }

    //first message to be sent
    //This command is sent by the sender to the server to add sender's key to the queue
    //Once the queue is secured only authorized messages can be sent to it.
    public static ByteBuffer sndSecure(byte[] senderAuthPublicKey) {
        ByteBuffer buffer = ByteBuffer.allocate(BLOCK_SIZE);
        buffer.put("SKEY ".getBytes(CHARSET));
        buffer.put(senderAuthPublicKey);
        buffer.flip();

        return buffer;
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

