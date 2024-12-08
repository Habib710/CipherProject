import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);
        while (true) {
            System.out.println("\n------- Encryption and Decryption Menu--------");
            System.out.println("1. AES");
            System.out.println("2. RSA");
            System.out.println("3. Rail Fence Cipher");
            System.out.println("4. Autokey Cipher");
            System.out.println("5. Exit");
            
            int userinput = scanner.nextInt();
            scanner.nextLine(); 

            switch (userinput) {
                case 1 -> aesProcess(scanner);
                case 2 -> rsaProcess(scanner);
                case 3 -> railFenceProcess(scanner);
                case 4 -> autokeyProcess(scanner);
                case 5 -> {
                    System.out.println("Exit");
                    scanner.close();
                    return;
                }
                default -> System.out.println("Invalid choice!");
            }}
        
    }

    // ....AES ....
    private static void aesProcess(Scanner scanner) throws Exception {
        System.out.println("\n--- AES Encryption and Decryption---");
        System.out.print("Do you want to (1) Encrypt or (2) Decrypt?  ");
        int input = scanner.nextInt();
        scanner.nextLine(); 

        System.out.print("Enter your key : ");
        String aesKeyInput = scanner.nextLine();
        if (aesKeyInput.length() != 16 || aesKeyInput.length() != 24 || aesKeyInput.length() != 32) {
            throw new IllegalArgumentException("AES key must be 16, 24, or 32 characters .");
        }
        SecretKey aesKey = new SecretKeySpec(aesKeyInput.getBytes(), "AES");

        if (input == 1) { 
            System.out.print("...Enter plaintext...: ");
            String plaintext = scanner.nextLine();
            byte[] encryptedData = encryptWithAES(aesKey, plaintext.getBytes());
            System.out.println("Encrypted : " + Base64.getEncoder().encodeToString(encryptedData));
        } else if (input == 2) { 
            System.out.print("...Enter encrypted text... : ");
            String encryptedText = scanner.nextLine();
            byte[] decryptedData = decryptWithAES(aesKey, Base64.getDecoder().decode(encryptedText));
            System.out.println("Decrypted: " + new String(decryptedData));
        } else {
            System.out.println("Invalid choice!");
        }
    }

    // ...RSA ..
    private static void rsaProcess(Scanner scanner) throws Exception {
        System.out.println("\n--- RSA ---");

        //..key will Auto generate ,,,as so long like 64 base key. 
        KeyPair keyPair = generateRSAKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        
        System.out.println("Public Key : " + Base64.getEncoder().encodeToString(publicKey.getEncoded()));

        System.out.print("...Enter plain message...: ");
        String plaintext = scanner.nextLine();
        byte[] encryptedData = encryptWithRSA(publicKey, plaintext.getBytes());
        System.out.println("Encrypted : " + Base64.getEncoder().encodeToString(encryptedData));

    }

    // ...Rail Cipher.. 
    private static void railFenceProcess(Scanner scanner) {
        System.out.println("\n=== Rail Fence Cipher ===");
        System.out.print("Do you want to (1) Encrypt or (2) Decrypt? : ");
        int input = scanner.nextInt();
        scanner.nextLine(); 

        System.out.print("Enter the number of rails: ");
        int rails = scanner.nextInt();
        scanner.nextLine(); 

        if (input == 1) { 
            System.out.print("Enter plaintext: ");
            String plaintext = scanner.nextLine();
            String encryptedText = encryptRailFence(plaintext, rails);
            System.out.println("Encrypted: " + encryptedText);
        } else if (input == 2) { 
            System.out.print("Enter encrypted text: ");
            String encryptedText = scanner.nextLine();
            String decryptedText = decryptRailFence(encryptedText, rails);
            System.out.println("Decrypted: " + decryptedText);
        } else {
            System.out.println("Invalid choice!..");
        }
    }

    // Autokey  .......
    private static void autokeyProcess(Scanner scanner) {
        System.out.println("\n=== Autokey Cipher ===");
        System.out.print("Do you want to (1) Encrypt or (2) Decrypt? : ");
        int action = scanner.nextInt();
        scanner.nextLine(); 

        System.out.print("Enter the key (single word): ");
        String key = scanner.nextLine();

        if (action == 1) { 
            System.out.print("Enter plaintext: ");
            String plaintext = scanner.nextLine();
            String encryptedText = encryptAutokey(plaintext, key);
            System.out.println("Encrypted: " + encryptedText);
        } else if (action == 2) { 
            System.out.print("Enter encrypted text: ");
            String encryptedText = scanner.nextLine();
            String decryptedText = decryptAutokey(encryptedText, key);
            System.out.println("Decrypted: " + decryptedText);
        } else {
            System.out.println("Invalid choice!");
        }
    }

    // AES ....
    public static byte[] encryptWithAES(SecretKey key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    public static byte[] decryptWithAES(SecretKey key, byte[] encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(encryptedData);
    }

    // RSA ....
    public static KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); 
        return keyPairGenerator.generateKeyPair();
    }

    public static byte[] encryptWithRSA(PublicKey publicKey, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    

    // Rail .....
    private static String encryptRailFence(String text, int rails) {
        char[][] rail = new char[rails][text.length()];
        boolean down = false;
        int row = 0, col = 0;

        for (char c : text.toCharArray()) {
            rail[row][col++] = c;
            if (row == 0 || row == rails - 1) down = !down;
            row += down ? 1 : -1;
        }

        StringBuilder result = new StringBuilder();
        for (char[] r : rail) {
            for (char c : r) if (c != 0) result.append(c);
        }
        return result.toString();
    }

    private static String decryptRailFence(String cipher, int rails) {
        char[][] rail = new char[rails][cipher.length()];
        boolean[] markers = new boolean[cipher.length()];
        int row = 0, col = 0;
        boolean down = true;

        for (int i = 0; i < cipher.length(); i++) {
            rail[row][col++] = '*';
            if (row == 0) down = true;
            if (row == rails - 1) down = false;
            row += down ? 1 : -1;
        }

        int index = 0;
        for (int i = 0; i < rails; i++) {
            for (int j = 0; j < cipher.length(); j++) {
                if (rail[i][j] == '*' && index < cipher.length()) {
                    rail[i][j] = cipher.charAt(index++);
                }
            }
        }

        StringBuilder result = new StringBuilder();
        row = 0;
        col = 0;
        for (int i = 0; i < cipher.length(); i++) {
            result.append(rail[row][col++]);
            if (row == 0) down = true;
            if (row == rails - 1) down = false;
            row += down ? 1 : -1;
        }
        return result.toString();
    }

   // Autokey ..
private static String encryptAutokey(String plaintext, String key) {
    StringBuilder cipher = new StringBuilder();
    plaintext = plaintext.replaceAll("[^A-Za-z]", "").toUpperCase();  
    String fullKey = key.toUpperCase() + plaintext;

    for (int i = 0; i < plaintext.length(); i++) {
        char p = plaintext.charAt(i);
        char k = fullKey.charAt(i);
        cipher.append((char) ((p - 'A' + k - 'A') % 26 + 'A'));
    }

    return cipher.toString();
}

private static String decryptAutokey(String cipher, String key) {
    StringBuilder plaintext = new StringBuilder();
    cipher = cipher.replaceAll("[^A-Za-z]", "").toUpperCase(); 
    StringBuilder fullKey = new StringBuilder(key.toUpperCase());

    for (int i = 0; i < cipher.length(); i++) {
        char c = cipher.charAt(i);
        char k = fullKey.charAt(i);  

       
        char decryptedChar = (char) ((c - 'A' - k + 'A' + 26) % 26 + 'A');
        plaintext.append(decryptedChar);

        
        fullKey.append(decryptedChar);  
    }

    return plaintext.toString();
}


}


