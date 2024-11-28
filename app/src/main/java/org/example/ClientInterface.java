package org.example;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

public class ClientInterface {

    private static final List<String> userNames = List.of("Alice", "Bob", "Zane", "Jun");

    private static Map<Integer, String> pseudoQueue = new HashMap<>();

    private static final List<String> commands = List.of("CREATE", "ACK", "CONFIRM");

    private static volatile int status = 3;

    public static void main(String[] args) throws InterruptedException {

        Scanner scanner = new Scanner(System.in);
        String input;


        //dummy thread, would be a network thread
        Thread statusThread = new Thread(() -> {
            while (true) {
                try {
                    Thread.sleep(30000); // Update every 2 seconds
                    status = (status + 1) % 3; // Cycle through 0, 1, 2
                    switch (status) {
                        case 1:
                            System.out.println("Please enter Command \"ACK\" to finalize creating SMQ queue to receive message from Bob");
                            break;
                        case 3:
                            System.out.println("You have received invitation from Alice to send message on SMQ queue");
                            System.out.println("Please enter Command \"CONFIRM\" to send agreement to send messages on queue SMQ1 for Alice");
                            break;
                        default:
                    }

                } catch (InterruptedException e) {
                    System.out.println("Status thread interrupted.");
                    break;
                }
            }
        });
        statusThread.start();

        // Prompt user to type their username
        System.out.println("Welcome to SMQ Protocol User Interface");
        System.out.println("Enter your username:");

        // Authentication loop
        while (true) {
            input = scanner.nextLine().trim();

            if (userNames.contains(input)) {
                System.out.println("Welcome, " + input + "!");
                break; // Exit authentication loop
            } else {
                System.out.println("Invalid username. Try again:");
            }
        }

        System.out.println("You can now enter commands. Type 'quit' to exit.");

        if (pseudoQueue.isEmpty()) {
            System.out.println("No queue available right now! You can type \"CREATE\" to start processing");
        }

        while (true) {
            System.out.print("Command: ");
            input = scanner.nextLine().trim();

            if (input.equalsIgnoreCase("quit")) {
                System.out.println("Goodbye!");
                statusThread.join();
                break; // Exit command loop
            } else {
                processInput(input, scanner);
            }
        }

        scanner.close();
    }

    private static void processInput(String input, Scanner scanner) {
        switch (input) {
            case "CREATE":
                System.out.print("Please type the name for the sender: ");
                String sender = scanner.nextLine().trim();
                System.out.println("SMQ creation process started with sender being: " + sender);
                break;

            case "ACK":
                System.out.println("Your SMQ has been created to receive messages!.");
                pseudoQueue.put(1, "SMQ1");
                System.out.println("Available queues");
                System.out.println("ID    Queue Name");
                for (Map.Entry<Integer, String> entry : pseudoQueue.entrySet()) {
                    System.out.println(entry.getKey() + "      " + entry.getValue());
                }
                break;

            case "CONFIRM":
                System.out.println("You have agreed to communicate with the receiver on the SMQ queue");
                break;

            default:
                System.out.println("Unknown command. Try 'help' for a list of commands.");
        }
    }
}
