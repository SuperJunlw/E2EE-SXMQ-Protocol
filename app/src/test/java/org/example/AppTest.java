/*
 * This source file was generated by the Gradle 'init' task
 */
package org.example;

import org.junit.jupiter.api.Test;

import javax.net.ssl.*;
import java.io.*;
import java.nio.ByteBuffer;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Random;

import static org.example.Commands.BLOCK_SIZE;
import static org.example.Commands.CHARSET;
import static org.junit.jupiter.api.Assertions.*;

class AppTest {
    @Test
    void appHasAGreeting() {
        App classUnderTest = new App();
        assertNotNull(classUnderTest.getGreeting(), "app should have a greeting");
    }

    @Test
    void testConnectingToSXMQServer() throws IOException, InterruptedException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        // SXMQ servers contain a 2, 3, or 4 certificate chain of trust, with a self-signed offline certificate as its
        // root. SXMQ states that we compare the root certificate with a fingerprint provided alongside the server url.
        // If it matches, trust the cert.
        TrustManager[] trustManagers = new TrustManager[]{
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }

                    public void checkClientTrusted(
                            java.security.cert.X509Certificate[] certs, String authType) {
                    }

                    public void checkServerTrusted(
                            java.security.cert.X509Certificate[] certs, String authType) {
                    }
                }
        };

        // SXMQ-enabled clients should be ditribuded with a trusted list of servers. Users can specify their own.
        String sxmqServer = "smp4.simplex.im";
        int sxmqPort = 5223;

        SSLContext sc = SSLContext.getInstance("TLSv1.3");
        sc.init(null, trustManagers, new java.security.SecureRandom());
        SSLSocketFactory sslSocketFactory = sc.getSocketFactory();
        SSLSocket socket = (SSLSocket) sslSocketFactory.createSocket(sxmqServer, sxmqPort);
        // Explicitly set the enabled protocols to TLS 1.2
        socket.setEnabledProtocols(new String[]{"TLSv1.2"});

        socket.startHandshake();
        InputStream in = socket.getInputStream();
        OutputStream out = socket.getOutputStream();

        // After the handshake, the first response from the server is the serverHello. This response specifies the
        // minimum and maximum supported protocol version alongside a sessionIdentifier.
        byte[] paddedServerHello = in.readNBytes(BLOCK_SIZE);
        System.out.println(new String(paddedServerHello, CHARSET));
        // All messages are padded to be a uniform 16384 bytes long. We strip the padding and print the bytes.
        byte[] mainBlockBytes = getMainBlockBytes(paddedServerHello);
        System.out.println("Server Hello:");
        printHex(mainBlockBytes);
        printSmpVersions(mainBlockBytes);
        byte[] sessionId = getShortString(mainBlockBytes, 4);
        // The session identifier included in the server hello will be included in future commands sent to the server.
        System.out.println("Session Identifier:");
        printHex(sessionId);

        // We create a clientHello containing the requested protocol version
        short protocolVersion = (short) 5;
        ByteBuffer clientHello = Commands.clientHello(protocolVersion);
        // Pad the request to 16384 bytes long
        byte[] paddedClientHello = Commands.paddedString(clientHello);
        // Send the client hello
        out.write(paddedClientHello);
        out.flush();
        System.out.println("Sent Client Hello.");

        // Constructing a PING command:
        // This is the most basic SXMQ command. It can be used to keep the transport connection alive or generate
        // traffic noise. The server simply returns an "ok" response.
        ByteBuffer ping = Commands.ping();
        // Generating a corrId. This is a 24 bit random array.
        byte[] randomCorrelationId = new byte[24];
        new Random().nextBytes(randomCorrelationId);
        ByteBuffer corrId = Commands.corrId(randomCorrelationId);
        // Generate a transmission containing the PING command
        ByteBuffer pingTransmission = Commands.transmission(
                Commands.shortString(sessionId),
                Commands.emptyShortString(),
                corrId,
                Commands.emptyShortString(),
                ping
        );
        // Generate a transportBlock containing the transmission. A transportBlock could contain multiple
        // transmissions. However, here it will only contain one.
        ByteBuffer pingTransportBlock = Commands.transportBlock(List.of(pingTransmission));
        // Pad the transportBlock to a size of 16384
        byte[] paddedPingTransportBlock = Commands.paddedString(pingTransportBlock);
        // Send the PING command
        out.write(paddedPingTransportBlock);
        out.flush();
        System.out.println("Sent PING.");
        // Read the OK response from the server.
        byte[] paddedPingResponse = in.readNBytes(BLOCK_SIZE);
        System.out.println("Server OK Response:");
        System.out.println(new String(paddedPingResponse, CHARSET));
    }

    public static void printHex(byte[] bytes) {
        for (byte b : bytes) {
            System.out.printf("%02X ", b);
        }
        System.out.println();
    }

    public static byte[] getMainBlockBytes(byte[] paddedString) {
        int high = paddedString[0];
        int low = paddedString[1];
        int length = (high << 8) + low;

        //testing if it is only padding
        for (int i=length+2; i<paddedString.length; i++) {
            if(paddedString[i] != '#') {
                System.out.println("not matching in padding for " + paddedString[i] + " and " + paddedString[i+1]);
            }
        }

        byte [] mainBlockBytes = new byte[length];
        for (int i=0; i<length; i++) {
            mainBlockBytes[i] = paddedString[i+2];
        }

        return mainBlockBytes;
    }

    public static void printSmpVersions(byte[] mainBlockBytes) {
        byte[] smpVersionBytes = new byte[]{mainBlockBytes[0], mainBlockBytes[1], mainBlockBytes[2], mainBlockBytes[3]};

        // Parse the bytes as two Word16 values (16-bit unsigned integers)
        ByteBuffer buffer = ByteBuffer.wrap(smpVersionBytes);
        int minVer = buffer.getShort() & 0xFFFF;  // Mask to treat as unsigned
        int maxVer = buffer.getShort() & 0xFFFF;

        System.out.println("SMP minVersion: " + minVer);
        System.out.println("SMP maxVersion: " + maxVer);
    }

    public static byte[] getShortString(byte[] bytes, int startIndex) {
        byte[] temp = new byte[bytes.length - startIndex];
        for (int i=0; i<temp.length; i++) {
            temp[i] = bytes[i+startIndex];
        }
        // Parse the shortString
        ByteBuffer buffer = ByteBuffer.wrap(temp);
        int length = buffer.get() & 0xFF; // Read length as unsigned byte

        if (length > buffer.remaining()) {
            throw new IllegalArgumentException("Invalid length: exceeds available data");
        }

        byte[] stringBytes = new byte[length];
        buffer.get(stringBytes); // Read the bytes based on the length
        return stringBytes;
    }
}
