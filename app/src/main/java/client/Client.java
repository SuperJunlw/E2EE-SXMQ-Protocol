package client;

import java.io.*;
import java.net.*;

public class Client {
    public static void main(String[] args) {
        // proxy address
        String hostname = "localhost";
        int port = 1312; // Port number

        try (Socket socket = new Socket(hostname, port)) {
            System.out.println("Connected to server successfully");

            //input and output streams
            OutputStream output = socket.getOutputStream();
            PrintWriter writer = new PrintWriter(output, true);
            InputStream input = socket.getInputStream();
            BufferedReader reader = new BufferedReader(new InputStreamReader(input));

            // Send command to the server
            //replace with actually command?
            String message = "command";
            writer.println(message);

            // server response
            String response = reader.readLine();
            System.out.println("Server: " + response);
        } catch (UnknownHostException ex) {
            System.out.println("Can't find server: " + ex.getMessage());
        } catch (IOException ex) {
            System.out.println("I/O exception: " + ex.getMessage());
        }
    }
}
