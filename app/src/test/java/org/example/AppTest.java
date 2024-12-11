/*
 * This source file was generated by the Gradle 'init' task
 */
package org.example;

import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;

import javax.net.ssl.*;
import java.io.IOException;
import java.io.InputStream;
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
        byte[] paddedResponse = IOUtils.toByteArray(in);
        System.out.println("Response " + new String(paddedResponse, CHARSET));
    }

    public static byte[] toPaddedString(String message) {
        int paddedLength = 16384;
        byte padSymbol = (byte)'#';
        byte[] messageBytes = message.getBytes(CHARSET);
        if (messageBytes.length >= 16384) {
            throw new RuntimeException("Message must be less than " + paddedLength + " bytes long. Currently it is " + messageBytes.length + " bytes long.");
        }
        short originalLength = (short) messageBytes.length;
        ByteBuffer paddedString = ByteBuffer.allocate(16384);
        paddedString.putShort(originalLength);
        paddedString.put(messageBytes);
        while(paddedString.hasRemaining()) {
            paddedString.put(padSymbol);
        }
        return paddedString.array();
    }
}
