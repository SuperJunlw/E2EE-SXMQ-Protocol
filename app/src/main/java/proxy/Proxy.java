package proxy;

import java.io.*;
import java.net.*;

public class Proxy {
    public static void main(String[] args) {
        int proxyPort = 2024; // Proxy port
        int serverPort = 1234; // Server port
        String serverHost = "localhost";

        try (ServerSocket proxySocket = new ServerSocket(proxyPort)) {

            while (true) {
                Socket clientSocket = proxySocket.accept();
                System.out.println("Client and proxy connected successfully");

                // Handle client connection
                new Thread(() -> processClientCommand(clientSocket, serverHost, serverPort)).start();
            }
        } catch (IOException e) {
            System.out.println("IO exception: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void processClientCommand(Socket client, String server, int serverPort) {
        try (
                Socket serverSocket = new Socket(server, serverPort); // Connect to the server
                InputStream clientInput = client.getInputStream();
                OutputStream clientOutput = client.getOutputStream();
                InputStream serverInput = serverSocket.getInputStream();
                OutputStream serverOutput = serverSocket.getOutputStream()
        ) {
            // sent client command to server
            Thread clientToServer = new Thread(() -> sentCommand(clientInput, serverOutput));
            clientToServer.start();

            // sent server response to client
            sentCommand(serverInput, clientOutput);

            clientToServer.join();
        } catch (IOException | InterruptedException e) {
            System.out.println("Proxy exception: " + e.getMessage());
            e.printStackTrace();
        }
    }

    //proxy sent message to server or client
    private static void sentCommand(InputStream input, OutputStream output) {
        try (BufferedInputStream bufferInoutStream = new BufferedInputStream(input);
             BufferedOutputStream bufferOutputStream = new BufferedOutputStream(output)) {
            byte[] buffer = new byte[1024];
            int bytes;
            while ((bytes = bufferInoutStream.read(buffer)) != -1) {
                bufferOutputStream.write(buffer, 0, bytes);
                bufferOutputStream.flush();
            }
        } catch (IOException e) {
            System.out.println("Proxy error sending message: " + e.getMessage());
        }
    }
}
