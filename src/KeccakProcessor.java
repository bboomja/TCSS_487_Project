/**
 * Implementation of KMACXOF256.
 *
 * @author Hyun Jeon
 * @version 1.0
 */
public class KeccakProcessor {

    /**
     * The round constants.
     */
    private static final long[] keccakfRndc = {
            0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL,
            0x8000000080008000L, 0x000000000000808BL, 0x0000000080000001L,
            0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL,
            0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
            0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L,
            0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
            0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L,
            0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
    };

    /**
     * Rotation offsets for the roh fuctions.
     */
    private static final int[] keccakfRotc = {
            1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
            27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
    };

    /**
     * The position for each word with respect to lane shifts in pi function.
     */
    private static final int[] keccakfPiln = {
            10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
            15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
    };

    /**
     * The theta function.
     * Adapted from https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
     * ref. section 3.2.1 NIST FIPS 202.
     * https://github.com/NWc0de/KeccakUtils/blob/master/src/crypto/keccak/Keccak.java
     *
     * @param inputState the input state
     * @return the output state
     */
    private static long[] theta(long[] inputState) {
        long[] outputState = new long[25];
        long[] C = new long[5];

        for (int i = 0; i < 5; i++) {
            C[i] = inputState[i] ^ inputState[i + 5] ^ inputState[i + 10] ^ inputState[i + 15] ^ inputState[i + 20];
        }

        for (int i = 0; i< 5; i++) {
            long d = C[(i + 4) % 5] ^ rotl64(C[(i + 1) % 5], 1);

            for (int j = 0; j < 5; j++) {
                outputState[i + 5 * j] = inputState[i + 5 * j] ^ d;
            }
        }
        return outputState;
    }

    /**
     * Perform a left rotation on a 64-bit long integer.
     *
     * @param x the 64-bit integer to be rotated
     * @param y the number of positions to rotate x to the left
     * @return the rotated 64-bit integer
     */
    private static long rotl64(long x, long y) {
        // Rotate x to the left by y bits.
        return (x << y) | (x >>> (64 - y));
    }

    /**
     * Rho and Pi function.
     * Adapted from https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
     * ref. section 3.2.2-3 NIST FIPS 202.
     * https://github.com/NWc0de/KeccakUtils/blob/master/src/crypto/keccak/Keccak.java
     *
     * @param inputState the input state
     * @return the output state for rho and pi function
     */
    private static long[] rhoPi(long[] inputState) {
        long[] outputState = new long[25];

        // first value needs to be copied
        outputState[0] = inputState[0];

        long t = inputState[1], temp;

        int ind;

        for (int i = 0; i < 24; i++) {
            ind = keccakfPiln[i];
            temp = inputState[ind];
            outputState[ind] = rotl64(t, keccakfRotc[i]);
            t = temp;
        }

        return outputState;
    }

    /**
     * The chi function.
     * Adapted from https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
     * ref. section 3.2.4 NIST FIPS 202.
     * https://github.com/NWc0de/KeccakUtils/blob/master/src/crypto/keccak/Keccak.java
     *
     * @param inputState the input state, an array of 25 longs ref FIPS 202 sec. 3.1.2
     * @return the state after applying the chi function
     */
    private static long[] chi (long[] inputState) {
        long[] outputState = new long[25];

        for (int i = 0; i < 5; i ++) {
            for (int j = 0; j < 5; j++) {
                long tmp = ~inputState[(i + 1) % 5 + 5 * j] & inputState[(i + 2) % 5 + 5 * j];
                outputState[i + 5 * j] = inputState[i + 5 * j] ^ tmp;
            }
        }
        return outputState;
    }

    /**
     * The iota function.
     * Adapted from https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
     * ref. section 3.2.5 NIST FIPS 202.
     * https://github.com/NWc0de/KeccakUtils/blob/master/src/crypto/keccak/Keccak.java
     *
     * @param inputState the input state, an array of 25 longs ref FIPS 202 sec. 3.1.2
     * @param r the round
     * @return the state after the round constant has been xored with the first lane
     */
    private static long[] iota(long[] inputState, int r) {
        inputState[0] ^= keccakfRndc[r];
        return inputState;
    }
}
