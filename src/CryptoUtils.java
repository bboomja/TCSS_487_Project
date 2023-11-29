import java.math.BigInteger;
import java.util.Arrays;

/**
 * A utility class that provides cryptographic operations including hashing,
 * padding, and encoding.
 * This class is based on the Keccak cryptographic hash function.
 * This implementation was inspired by:
 * - https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
 * - https://github.com/NWc0de/KeccakUtils/blob/master/src/crypto/keccak/KCrypt.java
 */
public class CryptoUtils {
    /**
     * The SHAKE256 function.
     * Produces a variable length message digest based on the keccak-f permutations.
     *
     * @param in The input byte array
     * @param bitLen The desired bit length of the output
     * @return A byte array representing the message digest
     */
    public static byte[] SHAKE256(byte[] in, int bitLen) {
        // Copy the input byte array to create a new array.
        byte[] uin = Arrays.copyOf(in, in.length + 1);
        // The rate is fixed at 136 bytes, calculate the number of bytes to pad.
        int bytesToPad = 136 - in.length % (136);
        // Perform padding and add the padding suffix.
        uin[in.length] = bytesToPad == 1 ? (byte) 0x9f : 0x1f;
        // Calculate the SHAKE256 hash using the sponge construction and return it.
        return sponge(uin, bitLen, 512);
    }

    /**
     * The cSHAKE256 function.
     * Implements the sponge function and then concatenates bits.
     *
     * @param in The input byte array
     * @param bitLength The desired bit length of the output
     * @param functionName A byte array representing the function's name
     * @param customStr A custom string as byte array
     * @return A byte array representing the message digest
     */
    public static byte[] cSHAKE256(byte[] in, int bitLength, byte[] functionName, byte[] customStr) {
        // If both function name and custom string are empty, fallback to SHAKE 256
        if (functionName.length == 0 && customStr.length == 0) {
            return SHAKE256(in, bitLength);
        }

        // Concatenate the encoded functionName and customStr
        byte[] fin = concat(encodeString(functionName), encodeString(customStr));
        // Pad the concatenated data to a multiple of 136 bytes (the rate of cSHAKE256)
        fin = concat(bytePad(fin, 136), in);
        // Append a 0x04 byte (byte indicating cSHAKE) to the final data
        fin = concat(fin, new byte[] {0x04});
        // Calculate the cSHAKE256 hash using the sponge construction and return it
        return sponge(fin, bitLength, 512);
    }

    /**
     * The KMACXOF256 function.
     * Produces a plain cryptographic hash text.
     *
     * @param key The key as byte array
     * @param message The input byte array
     * @param outputBitLength The desired bit length of the output
     * @param customization A custom string as byte array
     * @return A byte array representing the hash text
     */
    public static byte[] KMACXOF256(byte[] key, byte[] message, int outputBitLength, byte[] customization) {
        // Concatenate the key with the input data, padding the key to 136 bytes
        byte[] paddedKey = concat(concat(bytePad(encodeString(key),136), message), rightEncode(BigInteger.ZERO));
        // Use the cSHAKE256 function with the specified custom string and "KMAC" as the function name
        return cSHAKE256(paddedKey, outputBitLength, "KMAC".getBytes(), customization);
    }
    /**
     * A function to perform right encoding of bits.
     * Encodes the bits of BigInteger X onto the right side of the byte array.
     *
     * @param num The BigInteger to be encoded
     * @return A byte array with the encoded BigInteger
     */
    private static byte[] rightEncode(BigInteger num) {
        // Check if num is within the acceptable range.
        if (num.compareTo(BigInteger.valueOf(2).pow(2040)) >= 0) {
            throw new IllegalArgumentException("x should be less than 2^2040");
        }

        int byteCount = 1;
        // Find the appropriate value of byteCount to represent num.
        while (num.compareTo(new BigInteger(String.valueOf((int)Math.pow(2, (8 * byteCount))))) != -1) {
            byteCount++;
        }
        // Get the byte representation of num.
        byte[] numberBytes = num.toByteArray();

        // If the first byte of numberBytes is 0 and there are more bytes, remove the leading zero.
        if ((numberBytes[0] == 0) && (numberBytes.length > 1)) {
            byte[] temp = new byte[numberBytes.length - 1];
            System.arraycopy(numberBytes, 1, temp, 0, numberBytes.length - 1);
            numberBytes = temp;
        }

        byte[] output = new byte[numberBytes.length + 1];

        for (int i = 0; i < numberBytes.length; i++) {
            output[numberBytes.length - (i+1)] = numberBytes[i];
        }
        // Set the first byte of the output as the value of byteCount.
        output[0] =(byte) byteCount;

        return output;
    }

    /**
     * Encodes the given BigInteger onto the left side of the byte array.
     *
     * @param num The BigInteger to be encoded
     * @return A byte array with the left-encoded BigInteger
     */
    private static byte[] leftEncode(BigInteger num) {
        // Check if num is within the acceptable range.
        if (num.compareTo(BigInteger.valueOf(2).pow(2040)) >= 0) {
            throw new IllegalArgumentException("x should be less than 2^2040");
        }

        int n = 1;
        // Find the appropriate value of n to represent num.
        while (num.compareTo(new BigInteger(String.valueOf((int)Math.pow(2, (8*n))))) != -1) {
            n++;
        }

        // Get the byte representation of num.
        byte[] xBytes = num.toByteArray();
        // If the first byte is 0 and there are more bytes, remove the leading zero.
        if ((xBytes[0] == 0) && (xBytes.length > 1)) {
            byte[] temp = new byte[xBytes.length - 1];
            System.arraycopy(xBytes, 1, temp, 0, xBytes.length - 1);
            xBytes = temp;
        }
        // Create the output byte array.
        byte[] output = new byte[xBytes.length + 1];
        for (int i = 0; i < xBytes.length; i++) {
            output[xBytes.length - (i)] = xBytes[i];
        }

        output[0] =(byte) n;
        return output;
    }

    /**
     * Encodes the provided byte array into another byte representation.
     *
     * @param byteArray The byte array to be encoded
     * @return Encoded byte array
     */
    private static byte[] encodeString(byte[] byteArray) {
        if (byteArray == null || byteArray.length == 0) {
            // If the input byte array is null or empty, encode it as zero.
            return leftEncode(BigInteger.ZERO);
        } else {
            // Encode the length of the byte array in bits as a prefix.
            BigInteger lengthInBits = BigInteger.valueOf(byteArray.length << 3);
            byte[] lengthPrefix = leftEncode(lengthInBits);

            // Concatenate the length prefix with the original byte array.
            return concat(lengthPrefix, byteArray);
        }
    }

    /**
     * Performs padding on the provided byte array.
     *
     * @param arr Byte array to be padded
     * @param value Width of the padding
     * @return Padded byte array
     */
    private static byte[] bytePad(byte[] arr, int value) {
        // SecondArray must be greater than 0
        if (value <= 0) {
            throw new IllegalArgumentException("Value must be greater than 0");
        }

        // Convert value to BigInteger and encode it into a byte array
        byte[] encoded = leftEncode(BigInteger.valueOf(value));
        // Calculate the length of the resulting byte array result
        byte[] result = new byte[value * ((encoded.length + arr.length + value - 1) / value)];

        // Concatenate encoded and arr into result
        System.arraycopy(encoded, 0, result, 0, encoded.length);
        System.arraycopy(arr,0,result,encoded.length, arr.length);

        for (int i = encoded.length + arr.length; i < result.length; i++) {
            result[i] = (byte) 0;
        }

        return result;
    }
    /**
     * Implements the sponge construction, a fundamental component of the Keccak algorithm.
     * The sponge function absorbs input data into the state, and then it's squeezed out.
     * - https://github.com/NWc0de/KeccakUtils/blob/master/src/crypto/keccak/KCrypt.java
     *
     * @param in The input bytes
     * @param bitLen The desired bit length of the output
     * @param capacity The capacity in bits which remains untouched by the sponge function
     * @return Output bytes after applying the sponge function
     */
    private static byte[] sponge(byte[] in, int bitLen, int capacity) {
        int rate = 1600 - capacity;
        // Pad the input to a multiple of the rate if needed.
        byte[] padded = in.length % (rate / 8) == 0 ? in : padTenOne(rate, in);
        // Convert the padded byte array into a 2D array of states.
        long[][] states = byteArrayToStates(padded, capacity);
        // Initialize the state to be used for Keccak processing.
        long[] stcml = new long[25];
        // Process each state in the sponge construction.
        for (long[] st : states) {
            stcml = KeccakProcessor.keccak(KeccakProcessor.xorStates(stcml, st), 1600, 24);
        }
        // Initialize the output long array.
        long[] out = {};
        int offset = 0;
        do {
            // Increase the size of the output long array.
            out = Arrays.copyOf(out, offset + rate / 64);
            // Copy the state into the output array.
            System.arraycopy(stcml, 0, out, offset, rate / 64);
            offset += rate / 64;
            // Apply Keccak permutation to the state.
            stcml = KeccakProcessor.keccak(stcml, 1600, 24);
        } while (out.length * 64 < bitLen);
        // Convert the output long array to a byte array of the specified bit length.
        return stateToByteArray(out, bitLen);
    }
    /**
     * Implements the pad10*1 padding scheme.
     * This is used in Keccak to ensure that the input data is a multiple of the rate.
     * The name "pad10*1" comes from the pattern of the padding: it always starts with a '1' bit,
     * is followed by a number of '0' bits, and ends with a '1' bit.
     * - https://github.com/NWc0de/KeccakUtils/blob/master/src/crypto/keccak/KCrypt.java
     *
     * @param rate The rate in bits
     * @param in The input bytes that need padding
     * @return The input bytes with the necessary padding applied
     */
    private static byte[] padTenOne(int rate, byte[] in) {
        // Calculate the number of bytes needed to pad the input to a multiple of the rate.
        int bytesToPad = (rate / 8) - in.length % (rate / 8);
        // Create a new byte array to store the padded result.
        byte[] padded = new byte[in.length + bytesToPad];

        for (int i = 0; i < in.length + bytesToPad; i++) {
            if (i < in.length) {
                // Copy the original bytes from the input to the padded array.
                padded[i] = in[i];
            } else if (i == in.length + bytesToPad - 1) {
                // Add the '10' padding, followed by '1'.
                padded[i] = (byte) 0x80; // '10' padding (binary: 10000000)
            } else {
                // Add zero padding.
                padded[i] = 0;
            }
        }

        return padded;
    }
    /**
     * Calculates the XOR of two given byte arrays.
     *
     * @param firstArray First byte array
     * @param secondArray Second byte array
     * @return Byte array after XOR operation
     */
    public static byte[] xorBytes(byte[] firstArray, byte[] secondArray) {
        // Create a new byte array to store the XOR result.
        byte[] out = new byte[firstArray.length];
        // Iterate through the elements of the input arrays.
        for (int i = 0; i < firstArray.length; i++) {
            // Perform a bitwise XOR operation between corresponding bytes of the two arrays.
            out[i] = (byte) (firstArray[i] ^ secondArray[i]);
        }
        return out;
    }

    /**
     * Concatenates two given byte arrays.
     *
     * @param firstArray First byte array
     * @param secondArray Second byte array
     * @return Concatenated byte array
     */
    public static byte[] concat(byte[] firstArray, byte[] secondArray) {
        // Create a new byte array to store the concatenated result.
        byte[] result = new byte[firstArray.length + secondArray.length];
        // Copy the contents of the firstArray to the beginning of the result.
        System.arraycopy(firstArray,0,result,0,firstArray.length);
        // Copy the contents of the secondArray after the firstArray in the result.
        System.arraycopy(secondArray,0,result,firstArray.length,secondArray.length);
        return result;
    }

    /**
     * Converts the provided byte array into its hexadecimal string representation.
     *
     * @param byteArray Byte array to be converted
     * @return Hexadecimal string representation of the byte array
     */
    public static String bytesToHexString(byte[] byteArray) {
        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < byteArray.length; i++) {
            // Convert each byte to a two-character hexadecimal representation and append to the StringBuilder.
            hex.append(String.format("%02X", byteArray[i]));
        }
        return hex.toString();
    }

    /**
     * Converts the provided state into a byte array.
     *
     * @param state The state to be converted
     * @param bitLen Desired bit length of the output
     * @return Byte array representation of the state
     */
    private static byte[] stateToByteArray(long[] state, int bitLen) {
        // Check if the state is long enough to produce the desired bit length.
        if (state.length * 64 < bitLen) {
            throw new IllegalArgumentException("State is of insufficient length to produced desired bit length.");
        }
        // Calculate the size of the output byte array based on the bit length.
        byte[] out = new byte[bitLen / 8];
        int wrdInd = 0; // Initialize the word index.
        while (wrdInd * 64 < bitLen) {
            long word = state[wrdInd++]; // Get the next word from the state.
            int fill = wrdInd * 64 > bitLen ? (bitLen - (wrdInd - 1) * 64) / 8 : 8;
            // Extract individual bytes from the word and place them in the output array.
            for (int b = 0; b < fill; b++) {
                byte ubt = (byte) (word>>>(8 * b) & 0xFF); // Extract a byte from the word.
                out[(wrdInd - 1) * 8 + b] = ubt; // Place the byte in the output array.
            }
        }

        return out;
    }
    /**
     * Converts a byte array into an array of states. Each state is represented as an array of longs.
     *
     * @param in Byte array to be converted
     * @param cap Capacity which determines the number of bits that are unaffected by the transformation
     * @return An array of states derived from the input byte array
     */
    private static long[][] byteArrayToStates(byte[] in, int cap) {

        long[][] states = new long[(in.length * 8)/(1600 - cap)][25];
        int offset = 0;
        for (int i = 0; i < states.length; i++) {
            long[] state = new long[25];
            for (int j = 0; j < (1600 - cap) / 64; j++) {
                // Convert the next 8 bytes from the input array into a long word.
                long word = bytesToWord(offset, in);
                state[j] = word; // Assign the word to the state array.
                offset += 8; // Move the offset to the next 8 bytes.
            }

            states[i] = state; // Assign the state array to the states 2D array.
        }
        return states;
    }

    /**
     * Converts the provided byte range into a 64-bit word.
     *
     * @param offset The starting position in the byte array
     * @param in The byte array
     * @return 64-bit word
     */
    private static long bytesToWord(int offset, byte[] in) {
        // Check if the byte range is reachable within the input array.
        if (in.length < offset + 8) {
            throw new IllegalArgumentException("index out of range.");
        }

        long word = 0L;
        for (int i = 0; i < 8; i++) {
            // Extract each byte from the input array, cast it to a long, and shift it to its position.
            // The "& 0xff" mask ensures that the byte is treated as an unsigned byte.
            word += (((long)in[offset + i]) & 0xff)<<(8*i);
        }
        return word;
    }
}
