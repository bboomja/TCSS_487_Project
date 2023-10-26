import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Scanner;

/**
 * This is the main class implementation of KMACXOF256 functionality.
 * This class implements all the necessary functionalities to provide the required services.
 * This implementation was inspired by:
 * - https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
 * - https://github.com/NWc0de/KeccakUtils/blob/master/src/crypto/keccak/KCrypt.java
 */
public class Main {

    /**
     * Main method which drives the entire application inside the main class.
     * It orchestrates all the methods inside this class and handles user input.
     *
     * @param args The command-line arguments
     */
    public static void main(String[] args) {
        Scanner userInput = new Scanner(System.in);
        int categoryResponse = selectCategoryPrompt(userInput);

        switch (categoryResponse) {
            case 1:
                do {
                    selectService(userInput);
                } while (repeat(userInput));
                userInput.close();
            case 2:
                System.out.println("Exiting the application.");
        }

    }

    /**
     * Generates a secure random variable.
     */
    private static SecureRandom sr = new SecureRandom();

    private static byte[] previousEncrypt;

    /**
     * Prompt the user to select a category of service.
     * The user can choose either SHA-3 cryptographic Hashing or Exit the App.
     *
     * @param userIn The Scanner object for user input.
     * @return An integer representing the selected category: 1 for SHA-3 Cryptographic Hashing, 2 for Exit.
     */
    private static int selectCategoryPrompt(final Scanner userIn) {
        String menuPrompt = "Please choose a category of service by entering the corresponding number:\n" +
                "    1) SHA-3 Cryptographic Hashing\n" +
                "    2) Exit the Application\n";
        int response = getIntInRange(userIn, menuPrompt, 1, 4);
        if (response == 1) {
            return 1;
        } else {
            return 2;
        }
    }

    /**
     * Prompt the user to select a KMAC service and input method.
     * The user can choose to compute a plain cryptographic hash, compute an authentication tag (MAC),
     * encrypt a given data file, or decrypt a given symmetric cryptogram.
     *
     * @param userInput The Scanner object for user input
     */
    private static void selectService(final Scanner userInput) {
        String menu = "Please enter the corresponding number of the service you would like to use:\n" +
                "    1) Compute a plain cryptographic hash\n" +
                "    2) Compute an authentication tag (MAC)\n" +
                "    3) Encrypt a given data file\n" +
                "    4) Decrypt a given symmetric cryptogram\n";
        int response = getIntInRange(userInput, menu, 1, 4);
        switch (response) {
            case 1:
                plainHashService(inputPrompt(userInput));
                break;
            case 2:
                authenticationTagService(inputPrompt(userInput));
                break;
            case 3:
                encryptionService();
                break;
            default:
                decryptService(decryptPreviousCryptogram(userInput));
                break;
        }
    }


    /**
     * Prompt the user to choose the input format: file or user input text through the command line.
     *
     * @param userIn The Scanner object for user input
     * @return A String indicating the chosen input format: "file" or "user input text".
     */
    private static String inputPrompt(Scanner userIn) {
        String menuPrompt = "Choose the input format:\n" +
                "    1) File\n" +
                "    2) User input text through the command line\n";
        int input = getIntInRange(userIn, menuPrompt, 1, 2);
        if (input == 1) {
            return "file";
        } else {
            return "user input";
        }
    }

    /**
     * Prompt the user to choose the input format for decryption: most recently encrypted data (requires
     * using encryption service first) or user input cryptogram.
     *
     * @param userInput The Scanner object for user input.
     * @return A string indicating the chosen input format.
     */
    private static String decryptPreviousCryptogram(Scanner userInput) {
        String menu = "Choose the input format for decryption:\n" +
                "    1) Most recently encrypted (requires using encryption service first)\n" +
                "    2) User input cryptogram\n";
        int input = getIntInRange(userInput, menu, 1, 2);
        if (input == 1) {
            return "most recently encrypted";
        } else {
            return "user input";
        }
    }

    /**
     * Ask the user if they want to repeat the program, where the user chooses whether to proceed or halt the program.
     *
     * @param userInput The Scanner object for user input
     * @return A boolean indicating whether the user wants to use another service
     */
    private static boolean repeat(final Scanner userInput) {
        System.out.println("\nDo you want to perform another operation? (Y/N)");
        String s = userInput.next();
        System.out.println();
        return (s.equalsIgnoreCase("Y") || s.equalsIgnoreCase ("yes"));
    }


    /**
     * Compute a plain cryptographic hash based on the selected input source.
     *
     * @param input The chosen input source
     */
    private static void plainHashService(final String input) {
        byte[] byteArray;
        String theString = null;
        Scanner userInput = new Scanner(System.in);

        if (input.equals("file")) {
            File inputFile = getInputFile(userInput);
            theString = fileToString(inputFile);
        } else if (input.equals("user input")) {
            System.out.println("Please enter a phrase to be hashed: ");
            theString = userInput.nextLine();
        }

        assert theString != null;
        byteArray = theString.getBytes();
        byteArray = CryptoUtils.KMACXOF256("".getBytes(), byteArray, 512, "D".getBytes());
        System.out.println(CryptoUtils.bytesToHexString(byteArray));
    }

    /**
     * Compute an authentication tag (MAC) based on the selected input source.
     *
     * @param input The chosen input source
     */
    private static void authenticationTagService(final String input) {
        //get user input aas either "file" or "user input"
        byte[] byteArray;
        String theText = null;
        String passphrase = null;
        Scanner userInput = new Scanner(System.in);

        if (input.equals("file")) { //input from file
            File inFile = getInputFile(userInput);
            theText = fileToString(inFile);
        } else if (input.equals("user input")) { //input from command line
            System.out.println("Please enter the Text you want to be hashed: ");
            theText = userInput.nextLine();
        }

        System.out.println("Please enter a passphrase: ");
        passphrase = userInput.nextLine();
        assert theText != null;
        byteArray = theText.getBytes();
        byteArray = CryptoUtils.KMACXOF256(passphrase.getBytes(), byteArray, 512, "T".getBytes());
        System.out.println(CryptoUtils.bytesToHexString(byteArray));
    }

    /**
     * Encrypts a given data file using symmetric encryption with KMAC.
     */
    private static void encryptionService() {
        Scanner userIn = new Scanner(System.in);
        File theFile = getInputFile(userIn);

        if (theFile == null) {
            return;
        }

        String theFileContent = fileToString(theFile);
        String thePassphrase;
        byte[] byteArray = theFileContent.getBytes();
        System.out.println("Please enter a passphrase: ");
        thePassphrase = userIn.nextLine();
        previousEncrypt = encryptKMAC(byteArray, thePassphrase);
        System.out.println(CryptoUtils.bytesToHexString(previousEncrypt));
    }

    /**
     * Decrypts a given symmetric cryptogram to plain text using KMAC-based decryption.
     *
     * @param input The chosen input format for decryption.
     */
    private static void decryptService(String input) {
        Scanner userIn = new Scanner(System.in);
        String thePassphrase;
        byte[] decryptedByteArray = new byte[0];
        System.out.println("Please enter a passphrase you used for encryption: ");
        thePassphrase = userIn.nextLine();

        if (input.equals("prev encrypt")) {
            decryptedByteArray = decryptKMAC(previousEncrypt, thePassphrase);
        } else if (input.equals("user input")) {
            System.out.println("\nPlease input a cryptogram in hex string format in one line (spaces okay, NO NEW LINES!!!!!): \n");
            String userString = userIn.nextLine();
            byte[] hexBytes = CryptoUtils.hexStringToBytes(userString);
            decryptedByteArray = decryptKMAC(hexBytes, thePassphrase);
        }

        System.out.println("\nDecryption in Hex format:\n" + CryptoUtils.bytesToHexString(decryptedByteArray));
        System.out.println("\nThe Plain Text:\n" + new String (decryptedByteArray, StandardCharsets.UTF_8));
    }

    /**
     * Encrypts a given message using symmetric encryption with KMAC.
     *
     * @param m The message to be encrypted
     * @param pw The passphrase for encryption
     * @return The encrypted message
     */
    private static byte[] encryptKMAC(byte[] m, String pw) {
        byte[] rand = new byte[64];
        sr.nextBytes(rand);

        //squeeze bits from sponge
        byte[] keka = CryptoUtils.KMACXOF256(CryptoUtils.concat(rand, pw.getBytes()), "".getBytes(), 1024, "S".getBytes());
        byte[] ke = new byte[64];
        System.arraycopy(keka,0,ke,0,64);
        byte[] ka = new byte[64];
        System.arraycopy(keka, 64,ka,0,64);

        byte[] c = CryptoUtils.KMACXOF256(ke, "".getBytes(), (m.length * 8), "SKE".getBytes());
        c =  CryptoUtils.xorBytes(c, m);
        byte[] t = CryptoUtils.KMACXOF256(ka, m, 512, "SKA".getBytes());

        return CryptoUtils.concat(CryptoUtils.concat(rand, c), t);
    }

    /**
     * Decrypts a symmetric cryptogram using the KMAC decryption algorithm.
     *
     * @param cryptogram The symmetric cryptogram to decrypt
     * @param pw The passphrase used for encryption
     * @return The decrypted message
     */
    private static byte[] decryptKMAC(byte[] cryptogram, String pw) {
        byte[] rand = new byte[64];
        //get 512-bit random number from the beginning of cryptogram
        System.arraycopy(cryptogram, 0, rand, 0, 64);

        //retrieving the encrypted message of the previous encryption
        byte[] in = Arrays.copyOfRange(cryptogram, 64, cryptogram.length - 64);

        //get tag  appended to cryptogram
        byte[] tag = Arrays.copyOfRange(cryptogram, cryptogram.length - 64, cryptogram.length);

        //sponge squeezing of bits
        byte[] keka = CryptoUtils.KMACXOF256(CryptoUtils.concat(rand, pw.getBytes()), "".getBytes(), 1024, "S".getBytes());
        byte[] ke = new byte[64];
        System.arraycopy(keka,0,ke,0,64);
        byte[] ka = new byte[64];
        System.arraycopy(keka, 64,ka,0,64);

        byte[] m = CryptoUtils.KMACXOF256(ke, "".getBytes(), (in.length*  8), "SKE".getBytes());
        m = CryptoUtils.xorBytes(m, in);

        byte[] tPrime = CryptoUtils.KMACXOF256(ka, m, 512, "SKA".getBytes());

        if (Arrays.equals(tag, tPrime)) {
            return m;
        }
        else {
            throw new IllegalArgumentException("Tags didn't match");
        }
    }

    /**
     * Gets an integer input from the user within a specified range.
     *
     * @param userInput The Scanner object for user input
     * @param prompts The prompt message for user input
     * @param minMenuInput The minimum allowed input value
     * @param maxMenuInput The maximum allowed input value
     * @return The user's integer input within the specified range
     */
    public static int getIntInRange(final Scanner userInput, final String prompts,
                                    final int minMenuInput, final int maxMenuInput) {
        int input = getInteger(userInput, prompts);
        while (input < minMenuInput || input > maxMenuInput) {
            System.out.print("Input out of range.\nPlease enter a number that corresponds to a menu prompt.\n");
            input = getInteger(userInput, prompts);
        }
        return input;
    }

    /**
     * Get an integer input from the user.
     *
     * @param userInput The Scanner object for user input
     * @param prompts The prompt message for user input
     * @return The user's integer input
     */
    public static int getInteger(final Scanner userInput, final String prompts) {
        System.out.println(prompts);
        while (!userInput.hasNextInt()) {
            userInput.next();
            System.out.println("Invalid input. Please enter an integer.");
            System.out.println(prompts);
        }
        return userInput.nextInt();
    }

    /**
     * Prompts the user to enter the full path of a file and returns a File.
     *
     * @param userIn The Scanner object for user input
     * @return A File object representing the user-specified file or null if the user chooses to go back
     */
    public static File getInputFile(final Scanner userIn) {
        File theFile = null;
        String filePrompt = "Please enter the full path of the file (or type 'BACK' to go back): ";

        while (true) {
            System.out.println(filePrompt);
            String inputPath = userIn.nextLine();

            if (inputPath.equalsIgnoreCase("BACK")) {
                return null;
            }

            theFile = new File(inputPath);
            if (theFile.exists()) {
                break;
            } else {
                System.out.println("Error: File doesn't exist.");
            }
        }

        return theFile;
    }

    /**
     * Converts the contents of a File object to a string.
     *
     * @param theFile The File object to convert to a string.
     * @return        A string containing the contents of the file.
     */
    public static String fileToString(final File theFile) {
        String theString = null;
        try {
            theString = new String(Files.readAllBytes(theFile.getAbsoluteFile().toPath()));
        } catch (IOException e) {
            e.printStackTrace();
        }
        return theString;
    }

    /**
     * Writes the given contents to an output file.
     *
     * @param outputFile The File object representing the output file.
     * @param contents   The contents to write to the output file.
     */
    private static void writeOutputFile(File outputFile, String contents) {
        Scanner stringScan = new Scanner(contents);
        try {
            FileWriter fw = new FileWriter(outputFile);
            while (stringScan.hasNextLine()) {
                fw.write(stringScan.nextLine());
            }
            fw.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}
