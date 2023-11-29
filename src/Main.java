import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;

/**
 * This class provides a cryptographic operations such as hashing, authentication (MAC), encryption,
 * and decryption using the Keccak cryptographic hash algorithm.
 * This implementation is inspired by:
 * - https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
 * - https://github.com/NWc0de/KeccakUtils/blob/master/src/crypto/keccak/KCrypt.java
 *
 * @author Hyun Jeon
 * @version 1.0
 */
public class Main {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        while (true) {
            printOptions(); // Display the menu options.
            int option = scanner.nextInt();

            switch (option) {
                case 1:
                    handleHashingOption(scanner); // Call a method to handle option 1.
                    break;

                case 2:
                    handleAuthenticationOption(scanner); // Call a method to handle option 2.
                    break;

                case 3:
                    handleEncryptionOption(scanner); // Call a method to handle option 3.
                    break;

                case 4:
                    handleDecryptionOption(scanner); // Call a method to handle option 4.
                    break;

                case 5:
                    keyPair();
                    break;

                case 6:
                    handleDataEncryptionOption(scanner);
                    break;

                case 7:
                    decryptEC();
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
        System.out.println("5. Generate an elliptic curve key pair from a passphrase");
        System.out.println("6. Encrypt a data file under a given elliptic public key");
        System.out.println("7. Decrypt a data file encrypted with an elliptic public key");
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
        scanner.nextLine(); // Consume the newline character after reading the integer.
        byte[] inputBytes;
        byte[] hashBytes;

        switch (subOption) {
            case 1:
                System.out.println("Enter the file path:");
                String filePath = scanner.nextLine();
                inputBytes = readFileToByteArray(filePath); // Read the file content into a byte array.
                hashBytes = CryptoUtils.KMACXOF256("".getBytes(), inputBytes, 512, "D".getBytes());
                System.out.println("Hash of the file: " + CryptoUtils.bytesToHexString(hashBytes));
                break;

            case 2:
                System.out.println("Enter the text:");
                String inputText = scanner.nextLine();
                inputBytes = inputText.getBytes(); // Convert the text to bytes.
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

    private static void handleDataEncryptionOption(Scanner scanner) {
        scanner.nextLine();

        System.out.println("Enter the public key file path:");
        String publicKeyFilePath = scanner.nextLine();

        System.out.println("Enter the data file path:");
        String dataFilePath = scanner.nextLine();


        String outputFilePath = dataFilePath + "_encrypted.txt";

        encryptEC(publicKeyFilePath, dataFilePath, outputFilePath);
        System.out.println("Encrypted data saved to: " + outputFilePath);
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

    private static void keyPair() {
        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter your passphrase: ");
        String passphrase = scanner.nextLine();

        // s = 4 * KMACXOF256(pw, "", 448, "SK") (mod r)
        byte[] sBytes = CryptoUtils.KMACXOF256(passphrase.getBytes(), "".getBytes(), 448, "SK".getBytes());
        BigInteger s = new BigInteger(1, sBytes).multiply(BigInteger.valueOf(4)).mod(EllipticCurve.r);

        // V = s * G
        EllipticCurvePoint G = EllipticCurve.getG();
        EllipticCurvePoint V = EllipticCurve.exponentiation(G, s);

        // Print
        System.out.println("Generated Public Key: \n" + V.getX().toString(16) + "\n" + V.getY().toString(16));
        System.out.println();
        System.out.println("Generated Private Key: " + s.toString(16));
        System.out.println();

        // Save the file
        String currentDirectory = System.getProperty("user.dir");
        saveToFile("PublicKeyOutput.txt", V.getX().toString(16) + "\n" + V.getY().toString(16));
        saveToFile("PrivateKeyOutput.txt", s.toString(16));
        System.out.println();


        System.out.println("Public Key saved to: " + currentDirectory + "/PublicKeyOutput.txt");
        System.out.println("Private Key saved to: " + currentDirectory + "/PrivateKeyOutput.txt");
    }

    private static void encryptEC(String publicKeyFilePath, String dataFilePath, String outputFilePath) {
        try {
            EllipticCurvePoint publicKey = readPublicKeyFromFile(publicKeyFilePath);

            SecureRandom random = new SecureRandom();
            byte[] kBytes = new byte[56]; // 448 bits
            random.nextBytes(kBytes);
            BigInteger k = new BigInteger(1, kBytes).multiply(BigInteger.valueOf(4)).mod(EllipticCurve.r);

            // W = k * V, Z = k * G
            EllipticCurvePoint W = EllipticCurve.exponentiation(publicKey, k);
            EllipticCurvePoint G = EllipticCurve.getG();
            EllipticCurvePoint Z = EllipticCurve.exponentiation(G, k);

            byte[] keka = CryptoUtils.KMACXOF256(W.getX().toByteArray(), "".getBytes(), 2 * 448, "PK".getBytes());
            byte[] ke = Arrays.copyOfRange(keka, 0, keka.length / 2);
            byte[] ka = Arrays.copyOfRange(keka, keka.length / 2, keka.length);

            byte[] m = readFileToByteArray(dataFilePath);

            byte[] c = CryptoUtils.KMACXOF256(ke, "".getBytes(), m.length * 8, "PKE".getBytes());
            byte[] encryptedData = CryptoUtils.xorBytes(m, c);
            byte[] t = CryptoUtils.KMACXOF256(ka, m, 448, "PKA".getBytes());

            String encryptedDataHexString = bytesToHexString(encryptedData);
            System.out.println("Encrypted Data (Hex): " + encryptedDataHexString);

            // Writing the file
            try (java.io.OutputStream os = java.nio.file.Files.newOutputStream(java.nio.file.Paths.get(outputFilePath))) {
                os.write(Z.getX().toByteArray());
                os.write(Z.getY().toByteArray());
                os.write(c);
                os.write(t);
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.err.println("Error in encrypting the data file: " + e.getMessage());
        }
    }

    private static void decryptEC() {
        Scanner userInput = new Scanner(System.in);
        File inputFile;
        File outputFile = new File("DecryptedEC.txt");
        String passphrase;

        inputFile = getUserInputFile(userInput);

        System.out.println("Please enter the passphrase used to encrypt: ");
        passphrase = userInput.nextLine();

        try {
            String inputFileContents = fileToString(inputFile);
            Scanner stringScanner = new Scanner(inputFileContents);

            EllipticCurvePoint Z = new EllipticCurvePoint(new BigInteger(hexStringToBytes(stringScanner.nextLine())),
                    new BigInteger(hexStringToBytes(stringScanner.nextLine())));
            byte[] c = hexStringToBytes(stringScanner.nextLine());
            byte[] t = hexStringToBytes(stringScanner.nextLine());

            BigInteger s = new BigInteger(1, CryptoUtils.KMACXOF256(passphrase.getBytes(), "".getBytes(), 448, "SK".getBytes()))
                    .multiply(BigInteger.valueOf(4))
                    .mod(EllipticCurve.r);

            EllipticCurvePoint W = EllipticCurve.exponentiation(Z, s);

            byte[] keka = CryptoUtils.KMACXOF256(W.getX().toByteArray(), "".getBytes(), 2 * 448, "PK".getBytes());
            byte[] ke = Arrays.copyOfRange(keka, 0, keka.length / 2);
            byte[] ka = Arrays.copyOfRange(keka, keka.length / 2, keka.length);

            byte[] m = CryptoUtils.xorBytes(CryptoUtils.KMACXOF256(ke, "".getBytes(), c.length * 8, "PKE".getBytes()), c);
            byte[] tPrime = CryptoUtils.KMACXOF256(ka, m, 448, "PKA".getBytes());

            if (Arrays.equals(t, tPrime)) {
                java.nio.file.Files.write(outputFile.toPath(), m);
                System.out.println("Decryption successful. Data saved to: " + outputFile.getPath());
            } else {
                System.err.println("Decryption failed: Authentication tag does not match.");
            }
        } catch (IOException e) {
            System.err.println("Error reading the file: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("Error during decryption: " + e.getMessage());
        }
    }

    /**
     * Asks the user for a file path.
     * If correctly verified, the method will create a File object from that path.
     * @param userIn the scanner used when asking the user for the file path.
     * @return the File object created from the verified path.
     */
    public static File getUserInputFile(final Scanner userIn) {
        File theFile;
        boolean pathVerify = false;
        String filePrompt = "Please enter the full path of the file:";
        do {
            System.out.println(filePrompt);
            theFile = new File(userIn.nextLine());
            if (theFile.exists() && !theFile.isDirectory()) {
                pathVerify = true;
            } else {
                System.out.println("ERROR: File doesn't exist or is a directory. Please try again.");
            }
        } while (!pathVerify);

        return theFile;
    }

    public static String fileToString(final File theFile) {
        String theString = null;
        try {
            theString = new String(Files.readAllBytes(theFile.toPath()), StandardCharsets.UTF_8);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return theString;
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

    private static void saveToFile(String filename, String content) {
        try {
            FileWriter writer = new FileWriter(filename);
            writer.write(content);
            writer.close();
            System.out.println("Saved to " + filename);
        } catch (IOException e) {
            System.out.println("An error occurred while writing to " + filename);
            e.printStackTrace();
        }
    }

    /**
     * Read a public key from a given file and create an EllipticCurvePoint object.
     *
     * @param filePath the path to the public key file.
     * @return an EllipticCurvePoint representing the public key.
     * @throws IOException if there's an error reading the file.
     */
    private static EllipticCurvePoint readPublicKeyFromFile(String filePath) throws IOException {
        List<String> lines = java.nio.file.Files.readAllLines(java.nio.file.Paths.get(filePath));
        if (lines.size() < 2) {
            throw new IOException("Invalid public key file format.");
        }
        BigInteger x = new BigInteger(lines.get(0), 16);
        BigInteger y = new BigInteger(lines.get(1), 16);
        return new EllipticCurvePoint(x, y);
    }

    private static String bytesToHexString(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    private static byte[] hexStringToBytes(String hexString) {
        int len = hexString.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
                    + Character.digit(hexString.charAt(i + 1), 16));
        }
        return data;
    }
}
