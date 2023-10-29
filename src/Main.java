import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Scanner;

/**
 * This class provides a cryptographic operations such as hashing, authentication (MAC), encryption,
 * and decryption using the Keccak cryptographic hash algorithm.
 *
 * This implementation is inspired and adapted from:
 * - https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
 * - https://github.com/NWc0de/KeccakUtils/blob/master/src/crypto/keccak/KCrypt.java
 */
public class Main {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        while (true) {
            printOptions();
            int option = scanner.nextInt();

            switch (option) {
                case 1:
                    handleHashingOption(scanner);
                    break;

                case 2:
                    handleAuthenticationOption(scanner);
                    break;

                case 3:
                    handleEncryptionOption(scanner);
                    break;

                case 4:
                    handleDecryptionOption(scanner);
                    break;

                default:
                    System.out.println("Invalid option. Please choose a valid option.");
                    break;
            }

            System.out.print("Do you want to continue (yes/no): ");
            String continueOption = scanner.next().toLowerCase();
            if (!continueOption.equals("yes")) {
                System.out.println("Exiting the program.");
                break;
            }
        }
    }

    /**
     * Display available options to the user.
     */
    private static void printOptions() {
        System.out.println("Here are the options:");
        System.out.println("1. Compute a plain cryptographic hash");
        System.out.println("2. Compute an authentication tag (MAC) of a given file");
        System.out.println("3. Encrypt a given data file symmetrically");
        System.out.println("4. Decrypt a given symmetric cryptogram");
        System.out.println();
        System.out.print("Enter the option number: ");
    }

    /**
     * Handle the hashing operation based on user's sub-option selection.
     *
     * @param scanner the user input
     */
    private static void handleHashingOption(Scanner scanner) {
        System.out.println("Choose sub-option:");
        System.out.println("1. Compute a plain cryptographic hash of a file");
        System.out.println("2. Compute a plain cryptographic hash of text input");

        int subOption = scanner.nextInt();
        scanner.nextLine();
        byte[] inputBytes;
        byte[] hashBytes;

        switch (subOption) {
            case 1:
                System.out.println("Enter the file path:");
                String filePath = scanner.nextLine();
                inputBytes = readFileToByteArray(filePath);
                hashBytes = CryptoUtils.KMACXOF256("".getBytes(), inputBytes, 512, "D".getBytes());
                System.out.println("Hash of the file: " + CryptoUtils.bytesToHexString(hashBytes));
                break;

            case 2:
                System.out.println("Enter the text:");
                String inputText = scanner.nextLine();
                inputBytes = inputText.getBytes();
                hashBytes = CryptoUtils.KMACXOF256("".getBytes(), inputBytes, 512, "D".getBytes());
                System.out.println("Hash of the text: " + CryptoUtils.bytesToHexString(hashBytes));
                break;

            default:
                System.out.println("Invalid sub-option. Please choose a valid sub-option.");
                break;
        }
    }

    /**
     * Handle the authentication (MAC) operation based on user's sub-option.
     *
     * @param scanner the user input
     */
    private static void handleAuthenticationOption(Scanner scanner) {
        System.out.println("Choose sub-option:");
        System.out.println("1. Compute an authentication tag (MAC) of a given file under a given passphrase");
        System.out.println("2. Compute an authentication tag (MAC) of a text input under a given passphrase");

        int subOption = scanner.nextInt();
        scanner.nextLine();
        byte[] inputBytes;
        byte[] hashBytes;

        switch (subOption) {
            case 1:
                System.out.println("Enter the file path:");
                String filePath = scanner.nextLine();
                inputBytes = readFileToByteArray(filePath);

                System.out.println("Please enter a passphrase: ");
                String thePassphrase = scanner.nextLine();
                hashBytes = CryptoUtils.KMACXOF256(thePassphrase.getBytes(), inputBytes, 512, "T".getBytes());
                System.out.println("MAC of the file: " + CryptoUtils.bytesToHexString(hashBytes));
                break;

            case 2:
                System.out.println("Please enter a phrase to be hashed: ");
                String inputText = scanner.nextLine();
                System.out.println("Please enter a passphrase: ");
                String passphrase = scanner.nextLine();
                inputBytes = inputText.getBytes();
                hashBytes = CryptoUtils.KMACXOF256(passphrase.getBytes(), inputBytes, 512, "T".getBytes());
                System.out.println("MAC of the text: " + CryptoUtils.bytesToHexString(hashBytes));
                break;

            default:
                System.out.println("Invalid sub-option. Please choose a valid sub-option.");
                break;
        }
    }

    /**
     * Handle the encryption operation by encrypting the provided file using a passphrase.
     *
     * @param scanner the user input
     */
    private static void handleEncryptionOption(Scanner scanner) {
        scanner.nextLine();
        byte[] inputBytes;

        System.out.println("Enter the file path of the data to be encrypted:");
        String filePath = scanner.nextLine();
        inputBytes = readFileToByteArray(filePath);

        System.out.println("Please enter a passphrase: ");
        String passphrase = scanner.nextLine();

        byte[] encryptedData = encrypt(inputBytes, passphrase);

        System.out.println(CryptoUtils.bytesToHexString(encryptedData));

        // Save the encrypted data to a file
        String encryptedFilePath = filePath + ".encrypted";
        try {
            java.nio.file.Files.write(java.nio.file.Paths.get(encryptedFilePath), encryptedData);
            System.out.println("Encrypted data saved to: " + encryptedFilePath);
        } catch (java.io.IOException e) {
            System.err.println("Error writing to the encrypted file: " + e.getMessage());
        }
    }

    /**
     * Handle the decryption operation by decrypting an encrypted file using the provided passphrase.
     *
     * @param scanner the user input
     */
    private static void handleDecryptionOption(Scanner scanner) {
        scanner.nextLine();  // Consume leftover newline

        // Ask user for the path of the encrypted file
        System.out.println("Enter the path of the encrypted file:");
        String encryptedFilePath = scanner.nextLine();

        // Read the encrypted file content
        byte[] encryptedData = readFileToByteArray(encryptedFilePath);
        if (encryptedData.length == 0) {
            return;  // Exit if there was an error reading the file
        }

        // Ask user for the passphrase
        System.out.println("Please enter the passphrase used for encryption:");
        String passphrase = scanner.nextLine();

        try {
            // Decrypt the file
            byte[] decryptedData = decrypt(encryptedData, passphrase);

            System.out.println("Decrypted data:");
            System.out.println(new String(decryptedData));

        } catch (IllegalArgumentException e) {
            // Error during decryption, possibly due to wrong passphrase or tampered data
            System.err.println(e.getMessage());
        }
    }


    /**
     * Encrypt data using a provided passphrase.
     *
     * @param data the data
     * @param passphrase the passphrase
     * @return the encrypted data
     */
    private static byte[] encrypt(byte[] data, String passphrase) {
        SecureRandom sr = new SecureRandom();
        byte[] rand = new byte[64];
        sr.nextBytes(rand);

        byte[] keys = CryptoUtils.KMACXOF256(CryptoUtils.concat(rand, passphrase.getBytes()),
                "".getBytes(), 1024, "S".getBytes());
        byte[] keys1 = Arrays.copyOfRange(keys, 0, 64);
        byte[] keys2 = Arrays.copyOfRange(keys, 64, 128);

        byte[] c = CryptoUtils.KMACXOF256(keys1, "".getBytes(), (data.length * 8), "SKE".getBytes());
        c = CryptoUtils.xorBytes(c, data);
        byte[] t = CryptoUtils.KMACXOF256(keys2, data, 512, "SKA".getBytes());

        return CryptoUtils.concat(CryptoUtils.concat(rand, c), t);
    }

    /**
     * Decrypt data using a provided passphrase.
     *
     * @param data the data
     * @param passphrase the passphrase
     * @return the decrypted data
     */
    private static byte[] decrypt(byte[] data, String passphrase) {
        if (data.length <= 128) {
            throw new IllegalArgumentException("Invalid encrypted data");
        }

        byte[] rand = Arrays.copyOfRange(data, 0, 64);
        byte[] encrypted = Arrays.copyOfRange(data, 64, data.length - 64);
        byte[] givenTag = Arrays.copyOfRange(data, data.length - 64, data.length);

        byte[] keys = CryptoUtils.KMACXOF256(CryptoUtils.concat(rand, passphrase.getBytes()),
                "".getBytes(), 1024, "S".getBytes());
        byte[] keys1 = Arrays.copyOfRange(keys, 0, 64);
        byte[] keys2 = Arrays.copyOfRange(keys, 64, 128);

        byte[] decrypted = CryptoUtils.KMACXOF256(keys1, "".getBytes(),
                encrypted.length * 8, "SKE".getBytes());
        decrypted = CryptoUtils.xorBytes(decrypted, encrypted);

        byte[] calculatedTag = CryptoUtils.KMACXOF256(keys2, decrypted, 512, "SKA".getBytes());

        if (!Arrays.equals(givenTag, calculatedTag)) {
            throw new IllegalArgumentException("MAC tag does not match. Data may be corrupted or tampered with.");
        }

        return decrypted;
    }

    /**
     * Helper method to read a file's contents into a byte array.
     *
     * @param filePath the file path
     * @return the byte array
     */
    private static byte[] readFileToByteArray(String filePath) {
        try {
            return java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(filePath));
        } catch (java.io.IOException e) {
            System.err.println("Error reading the file: " + e.getMessage());
            return new byte[0];
        }
    }
}
