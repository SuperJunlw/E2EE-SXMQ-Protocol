package client;

import org.apache.commons.io.IOUtils;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;

public class Client {

    public static void main(String[] args) {
        // proxy address
        String hostname = "smp4.simplex.im";
        int port = 5223; // Port number

        try (Socket socket = new Socket(hostname, port)) {
            System.out.println("Connected to server successfully");

            //input and output streams
            OutputStream output = socket.getOutputStream();
            PrintWriter writer = new PrintWriter(output, true);
            InputStream input = socket.getInputStream();
            BufferedReader reader = new BufferedReader(new InputStreamReader(input));

            // Send command to the server
            //replace with actually command?
            String message = "PING";
            writer.println(message);

            // server response
            String response = IOUtils.toString(input, StandardCharsets.UTF_8);
            System.out.println("Server: " + response);
        } catch (UnknownHostException ex) {
            System.out.println("Can't find server: " + ex.getMessage());
        } catch (IOException ex) {
            System.out.println("I/O exception: " + ex.getMessage());
        }
    }
}
