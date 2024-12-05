package server;

import java.io.*;
import java.net.*;

public class Server {
    public static void main(String[] args) {
        // port number
        int port = 1234;
        try (ServerSocket sSocket = new ServerSocket(port)) {

            while (true) {
                Socket socket = sSocket.accept(); // Accept client connection
                System.out.println("connected successfully");

                // input and output streams
                InputStream input = socket.getInputStream();
                BufferedReader reader = new BufferedReader(new InputStreamReader(input));
                OutputStream output = socket.getOutputStream();
                PrintWriter writer = new PrintWriter(output, true);

                // Read message and respond
                String message = reader.readLine();
                System.out.println("Client: " + message);

                //replace with actual information?
                writer.println("Server respond: " + message);

                socket.close();
            }
        } catch (IOException ex) {
            System.out.println(ex.getMessage());
            ex.printStackTrace();
        }
    }
}
