package org.example;

import client.Message;
import com.iwebpp.crypto.TweetNaclFast;
import java.security.*;
import java.util.Arrays;

public class Utilities {



    //Generate a key pair for establishing a shared secret, use for encryption
    //EK and RDHK
    public static TweetNaclFast.Box.KeyPair GenerateSharedSecretKeyPair(){
        TweetNaclFast.Box.KeyPair keyPair = TweetNaclFast.Box.keyPair();
        return keyPair;
    }

    public static KeyPair GenerateCommandAuthorizeKeyPair() throws NoSuchAlgorithmException {

        // Generate the key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Ed25519");
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

//            // Extract the private and public keys
//            PrivateKey privateKey = keyPair.getPrivate();
//            PublicKey publicKey = keyPair.getPublic();
//            // Print the keys
//            System.out.println("Private Key: " + Arrays.toString(privateKey.getEncoded()));
//            System.out.println("Public Key: " + Arrays.toString(publicKey.getEncoded()));
        return keyPair;
    }

    //encrypt the message
    public static byte[] EncryptMessage(byte[] receiverPublic, byte[] senderPrivate, String msg, byte[] nonce){
        byte[] msgBytes = msg.getBytes();

        // creates a Box using recipient's public key and sender's own private key
        TweetNaclFast.Box senderBox = new TweetNaclFast.Box(receiverPublic, senderPrivate);

        // Encrypt the message
        byte[] encryptedMsg = senderBox.box(msgBytes, nonce);
        return encryptedMsg;
    }

    //decrypt the message
    public static String DecryptMessage(byte[] senderPublic, byte[] receiverPrivate, byte[] encryptedMsg, byte[] nonce){

        TweetNaclFast.Box box = new TweetNaclFast.Box(senderPublic, receiverPrivate);

        byte[] decryptedMsgByte = box.open(encryptedMsg, nonce);

        return new String(decryptedMsgByte);
    }


    // convert byte array to hex string
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    public static void main(String[] args) {
        try {
            // Generate key pairs for sender and receiver
            TweetNaclFast.Box.KeyPair senderKeyPair = TweetNaclFast.Box.keyPair();
            TweetNaclFast.Box.KeyPair receiverKeyPair = TweetNaclFast.Box.keyPair();

            Message msg = new Message("Hello world!");
            byte[] encryptedMsg = EncryptMessage(
                    receiverKeyPair.getPublicKey(),
                    senderKeyPair.getSecretKey(),
                    msg.getMessage(),
                    msg.getNonce()
            );

            System.out.println("Encrypted Message: " + bytesToHex(encryptedMsg));

            // Decrypt the message
            String decryptedMsg = DecryptMessage(
                    senderKeyPair.getPublicKey(),
                    receiverKeyPair.getSecretKey(),
                    encryptedMsg,
                    msg.getNonce()
            );


            System.out.println("Decrypted Message: " + decryptedMsg);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
