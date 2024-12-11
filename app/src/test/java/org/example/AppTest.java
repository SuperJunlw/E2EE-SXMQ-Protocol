/*
 * This source file was generated by the Gradle 'init' task
 */
package org.example;

import org.example.request.ClientHelloRequest;
import org.junit.jupiter.api.Test;

import javax.net.ssl.*;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;

class AppTest {
    static Charset CHARSET = StandardCharsets.US_ASCII;
    static int BLOCK_SIZE = 16384;

    @Test void appHasAGreeting() {
        App classUnderTest = new App();
        assertNotNull(classUnderTest.getGreeting(), "app should have a greeting");
    }

    @Test void testConnectingToSXMQServer() throws IOException, InterruptedException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        // Create a trust manager that does not validate certificate chains
        TrustManager[] trustAllCerts = new TrustManager[] {
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

        // Install the all-trusting trust manager
        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, trustAllCerts, new java.security.SecureRandom());
        SSLSocketFactory sslSocketFactory = sc.getSocketFactory();
        //SocketFactory sslSocketFactory = SSLSocketFactory.getDefault();
        SSLSocket socket = (SSLSocket) sslSocketFactory.createSocket("smp4.simplex.im", 5223);
        SSLParameters sslParameters = sc.getDefaultSSLParameters();;
        sslParameters.setApplicationProtocols(new String[]{"smp/1"});
        socket.setSSLParameters(sslParameters);
        InputStream in = socket.getInputStream();
        byte[] paddedServerHello = in.readNBytes(BLOCK_SIZE);
        System.out.println("paddedServerHello:");
        System.out.println(new String(paddedServerHello, CHARSET));
        OutputStream out = socket.getOutputStream();
        byte[] clientHello = new ClientHelloRequest((short) 11).getBytes();
        System.out.println("CONNECTED? " + socket.isConnected() + ", CLOSED? " + socket.isClosed() + ", BOUNDED? " + socket.isBound() + ", IN SHUTDOWN? " + socket.isInputShutdown() + ", OUT SHUTDOWN?" + socket.isOutputShutdown());
        byte[] paddedClientHello = toPaddedString(clientHello);
        out.write(paddedClientHello);
        System.out.println("Sent clientHello.");
        byte[] paddedResponse = in.readNBytes(BLOCK_SIZE);
        System.out.println("Response to clientHello:");
        System.out.println(new String(paddedResponse, CHARSET));
        byte[] ping = "PING".getBytes(CHARSET);
        byte[] paddedPing = toPaddedString(ping);
        out.write(paddedPing);
        byte[] paddedPingResponse = in.readNBytes(BLOCK_SIZE);
        System.out.println("Response to ping:");
        System.out.println(new String(paddedPingResponse, CHARSET));

    }

    public static byte[] toPaddedString(byte[] message) {
        byte padSymbol = (byte)'#';
        if (message.length >= BLOCK_SIZE) {
            throw new RuntimeException("Message must be less than " + BLOCK_SIZE + " bytes long. Currently it is " + message.length + " bytes long.");
        }
        short originalLength = (short) message.length;
        ByteBuffer paddedString = ByteBuffer.allocate(BLOCK_SIZE);
        paddedString.putShort(originalLength);
        paddedString.put(message);
        while(paddedString.hasRemaining()) {
            paddedString.put(padSymbol);
        }
        return paddedString.array();
    }
}
