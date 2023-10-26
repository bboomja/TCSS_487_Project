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
     * Adapted from:
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
     * Adapted from:
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
     * Adapted from:
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
     * Adapted from:
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
                long tmp = ~stateIn[(i+1) % 5 + 5*j] & stateIn[(i+2) % 5 + 5*j];
                stateOut[i + 5*j] = stateIn[i + 5*j] ^ tmp;
            }
        }
        return stateOut;
    }

    /**
     * Applies the round constatnt to the first word of the state.
     * Adapted from:
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
     * @param s1 First state
     * @param s2 Second state
     * @return Resultant state after XOR
     */
    public static long[] xorStates(long[] s1, long[] s2) {
        long[] out = new long[25];
        for (int i = 0; i < s1.length; i++) {
            out[i] = s1[i] ^ s2[i];
        }
        return out;
    }

    /**
     * Rotates the provided 64-bit lane.
     *
     * @param x 64-bit lane to be rotated
     * @param y Number of positions to rotate
     * @return Rotated 64-bit lane
     */
    private static long rotateLane64(long x, int y) {
        return (x << (y%64)) | (x >>> (64 - (y%64)));
    }

    /**
     * Calculates the floor of the base-2 logarithm of the provided integer.
     *
     * @param n The integer for which the logarithm is calculated
     * @return The floor value of the base-2 logarithm
     */
    private static int floorLog(int n) {
        if (n < 0) throw new IllegalArgumentException("Log is undefined for negative numbers.");
        int exp = -1;
        while (n > 0) {
            n = n>>>1;
            exp++;
        }
        return exp;
    }
}
