/**
 * This class provides methods for performing the various permutation and transformation steps
 * used in the Keccak algorithm.
 *
 * This implementation was inspired by:
 * - https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
 * - https://github.com/NWc0de/KeccakUtils/blob/master/src/crypto/keccak/KCrypt.java
 */
public class KeccakProcessor {
    // Constants for Keccak permutation
    private static final long[] keccakfRndc = {
            0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL,
            0x8000000080008000L, 0x000000000000808bL, 0x0000000080000001L,
            0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL,
            0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
            0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L,
            0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
            0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L,
            0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
    };

    private static final int[] keccakfPilane = {
            10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
            15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
    };

    private static final int[] keccakfRotc = {
            1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
            27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
    };

    /**
     * Method for the Keccak permutation.
     * - https://github.com/NWc0de/KeccakUtils/blob/master/src/crypto/keccak/KCrypt.java
     *
     * @param stateIn The input state
     * @param bitLen Bit Length
     * @param rounds Number of rounds
     * @return The permuted state
     */
    public static long[] keccak(long[] stateIn, int bitLen, int rounds) {
        long[] stateOut = stateIn;
        int l = floorLog(bitLen/25);
        for (int i = 12 + 2*l - rounds; i < 12 + 2*l; i++) {
            stateOut = iota(chi(rhoPhi(theta(stateOut))), i); // sec 3.3 FIPS 202
        }
        return stateOut;
    }

    /**
     * Performs the theta step of the Keccak algorithm.
     * - https://github.com/NWc0de/KeccakUtils/blob/master/src/crypto/keccak/KCrypt.java
     * - https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
     *
     * @param stateIn Input state array of size 25
     * @return New state array after applying the theta transformation
     */
    private static long[] theta(long[] stateIn) {
        long[] stateOut = new long[25];
        long[] C = new long[5];

        for (int i = 0; i < 5; i++) {
            C[i] = stateIn[i] ^ stateIn[i + 5] ^ stateIn[i + 10] ^ stateIn[i + 15] ^ stateIn[i + 20];
        }

        for (int i = 0; i < 5; i++) {
            long d = C[(i+4) % 5] ^ rotateLane64(C[(i+1) % 5], 1);

            for (int j = 0; j < 5; j++) {
                stateOut[i + 5*j] = stateIn[i + 5*j] ^ d;
            }
        }

        return stateOut;
    }

    /**
     * Performs the rho and phi steps of the Keccak algorithm.
     * - https://github.com/NWc0de/KeccakUtils/blob/master/src/crypto/keccak/KCrypt.java
     * - https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
     *
     * @param stateIn Input state array of size 25
     * @return New state array after applying the rho and phi transformations.
     */
    private static long[] rhoPhi(long[] stateIn) {
        long[] stateOut = new long[25];
        stateOut[0] = stateIn[0]; // copying first value
        long t = stateIn[1], temp;
        int ind;
        for (int i = 0; i < 24; i++) {
            ind = keccakfPilane[i];
            temp = stateIn[ind];
            stateOut[ind] = rotateLane64(t, keccakfRotc[i]);
            t = temp;
        }
        return stateOut;
    }

    /**
     * Performs the chi steps of the Keccak algorithm.
     * - https://github.com/NWc0de/KeccakUtils/blob/master/src/crypto/keccak/KCrypt.java
     * - https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
     *
     * @param stateIn Input state array of size 25
     * @return New state array after applying the chi transformation
     */
    private static long[] chi(long[] stateIn) {
        long[] stateOut = new long[25];
        for (int i = 0; i < 5; i++) {
            for (int j = 0; j < 5; j++) {
                long tmp = ~stateIn[(i + 1) % 5 + 5 * j] & stateIn[(i + 2) % 5 + 5 * j];
                stateOut[i + 5 * j] = stateIn[i + 5 * j] ^ tmp;
            }
        }
        return stateOut;
    }

    /**
     * Applies the round constatnt to the first word of the state.
     * - https://github.com/NWc0de/KeccakUtils/blob/master/src/crypto/keccak/KCrypt.java
     *
     * @param stateIn Input state array of size 25
     * @param round The round number
     * @return Modified state array after applying the round constant
     */
    private static long[] iota(long[] stateIn, int round) {
        stateIn[0] ^= keccakfRndc[round];
        return stateIn;
    }

    /**
     * Calculates the XOR of two given states.
     *
     * @param stateArray1 First state
     * @param stateArray2 Second state
     * @return Resultant state after XOR
     */
    public static long[] xorStates(long[] stateArray1, long[] stateArray2) {
        // Create a new array to store the result of the XOR operation.
        long[] out = new long[25];

        // Iterate through the elements of the input arrays.
        for (int i = 0; i < stateArray1.length; i++) {
            // Perform a bitwise XOR operation between corresponding elements of the two arrays.
            out[i] = stateArray1[i] ^ stateArray2[i];
        }

        // Return the resulting array containing the XORed values.
        return out;
    }


    /**
     * Rotates the provided 64-bit lane.
     *
     * @param value 64-bit lane to be rotated
     * @param rotationCount Number of positions to rotate
     * @return Rotated 64-bit lane
     */
    private static long rotateLane64(long value, int rotationCount) {
        // Calculate the effective rotation count within the range [0, 63].
        int effectiveRotation = rotationCount % 64;

        // Perform the circular left shift (rotation) operation.
        // Shift left by the effective rotation count, and also shift right by the complement to achieve circular rotation.
        return (value << effectiveRotation) | (value >>> (64 - effectiveRotation));
    }


    /**
     * Calculates the floor of the base-2 logarithm of the provided integer.
     *
     * @param num The integer for which the logarithm is calculated
     * @return The floor value of the base-2 logarithm
     */
    private static int floorLog(int num) {
        // Check if the input num is negative.
        if (num < 0) {
            throw new IllegalArgumentException("Negative numbers are not supported for logarithmic calculations.");
        }

        int exp = -1; // Initialize the exponent to -1.
        // Continue right-shifting num until it becomes zero.
        while (num > 0) {
            num = num >>> 1; // Right-shift num by one bit.
            exp++; // Increment the exponent.
        }
        // Return the floor logarithm base 2 of the input num.
        return exp;
    }
}
