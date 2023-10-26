import java.math.BigInteger;
import java.util.Arrays;

public class CryptoUtils {
    /**
     * The SHAKE256 function.
     * Produces a variable length message digest based on the keccak-f permutations.
     * This implementation was inspired by:
     * - https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
     * - https://github.com/NWc0de/KeccakUtils/blob/master/src/crypto/keccak/KCrypt.java
     *
     * @param in The input byte array
     * @param bitLen The desired bit length of the output
     * @return A byte array representing the message digest
     */
    public static byte[] SHAKE256(byte[] in, int bitLen) {
        byte[] uin = Arrays.copyOf(in, in.length + 1);
        int bytesToPad = 136 - in.length % (136); // rate is 136 bytes
        uin[in.length] = bytesToPad == 1 ? (byte) 0x9f : 0x1f; // pad with suffix defined in FIPS 202 sec. 6.2
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
        if (functionName.length == 0 && customStr.length == 0) return SHAKE256(in, bitLength);

        byte[] fin = concat(encodeString(functionName), encodeString(customStr));
        fin = concat(bytePad(fin, 136), in);
        fin = concat(fin, new byte[] {0x04});

        return sponge(fin, bitLength, 512);
    }

    /**
     * The KMACXOF256 function.
     * Produces a plain cryptographic hash text.
     *
     * @param key The key as byte array
     * @param in The input byte array
     * @param bitLength The desired bit length of the output
     * @param customString A custom string as byte array
     * @return A byte array representing the hash text
     */
    public static byte[] KMACXOF256(byte[] key, byte[] in, int bitLength, byte[] customString) {

        byte[] newX = concat(concat(bytePad(encodeString(key),136), in), rightEncode(BigInteger.ZERO));
        return cSHAKE256(newX, bitLength, "KMAC".getBytes(), customString);
    }
    /**
     * A function to perform right encoding of bits.
     * Encodes the bits of BigInteger X onto the right side of the byte array.
     *
     * @param x The BigInteger to be encoded
     * @return A byte array with the encoded BigInteger
     */
    private static byte[] rightEncode(BigInteger x) {
        //establishing the validity of x whi should be 0 <= x < 2^2040
        assert 0 < x.compareTo(new BigInteger(String.valueOf(Math.pow(2, 2040))));

        int n = 1;

        while (x.compareTo(new BigInteger(String.valueOf((int)Math.pow(2, (8*n))))) != -1) {
            n++;
        }

        byte[] xBytes = x.toByteArray();

        // handle exception where first byte is zero
        if ((xBytes[0] == 0) && (xBytes.length > 1)) {
            byte[] temp = new byte[xBytes.length - 1];
            System.arraycopy(xBytes, 1, temp, 0, xBytes.length - 1);
            xBytes = temp;
        }

        byte[] output = new byte[xBytes.length + 1];

        for (int i = 0; i < xBytes.length; i++) {
            output[xBytes.length - (i+1)] = xBytes[i];
        }

        output[0] =(byte)n;
        return output;
    }

    /**
     * Encodes the given BigInteger onto the left side of the byte array.
     *
     * @param x The BigInteger to be encoded
     * @return A byte array with the left-encoded BigInteger
     */
    private static byte[] leftEncode(BigInteger x) {
        //Establishing the Validity of X which should be 0 <= x < 2^2040
        assert 0 < x.compareTo(new BigInteger(String.valueOf(Math.pow(2, 2040))));

        int n = 1;

        while (x.compareTo(new BigInteger(String.valueOf((int)Math.pow(2, (8*n))))) != -1) {
            n++;
        }

        // representation of x in a bytearray
        byte[] xBytes = x.toByteArray();

        if ((xBytes[0] == 0) && (xBytes.length > 1)) {
            byte[] temp = new byte[xBytes.length - 1];
            System.arraycopy(xBytes, 1, temp, 0, xBytes.length - 1);
            xBytes = temp;
        }

        byte[] output = new byte[xBytes.length + 1];
        for (int i = 0; i < xBytes.length; i++) {
            //xBytes[i] = reverseBitsByte(xBytes[i]);
            output[xBytes.length - (i)] = xBytes[i];
        }

        output[0] =(byte)n;
        return output;
    }

    /**
     * Encodes the provided byte array into another byte representation.
     *
     * @param S The byte array to be encoded
     * @return Encoded byte array
     */
    private static byte[] encodeString(byte[] S) {
        if (S == null || S.length == 0) {
            return leftEncode(BigInteger.ZERO);
        } else {

            return concat(leftEncode(new BigInteger(String.valueOf(S.length << 3))), S);
        }
    }

    /**
     * Performs padding on the provided byte array.
     *
     * @param X Byte array to be padded
     * @param w Width of the padding
     * @return Padded byte array
     */
    private static byte[] bytePad(byte[] X, int w) {

        //validating the condition that w>0
        assert w > 0;

        byte[] wEnc = leftEncode(BigInteger.valueOf(w));

        byte[] z = new byte[w * ((wEnc.length + X.length + w - 1)/w)];

        /*
            Concatenates wEnc and X into z (z = wEnc || X)
            copies wEnc into z from z[0] to z[wEnc.length]
        */
        System.arraycopy(wEnc, 0, z, 0, wEnc.length);
        // copies X into z frm z[wEnc.length] till all X copied into z
        System.arraycopy(X,0,z,wEnc.length, X.length);


        for (int i = wEnc.length + X.length; i < z.length; i++) {
            z[i] = (byte) 0;
        }

        return z;
    }
    /**
     * Implements the sponge construction, a fundamental component of the Keccak algorithm.
     * The sponge function absorbs input data into the state, and then it's squeezed out.
     * Adapted from:
     * - https://github.com/NWc0de/KeccakUtils/blob/master/src/crypto/keccak/KCrypt.java
     *
     * @param in The input bytes
     * @param bitLen The desired bit length of the output
     * @param cap The capacity in bits which remains untouched by the sponge function
     * @return Output bytes after applying the sponge function
     */
    private static byte[] sponge(byte[] in, int bitLen, int cap) {
        int rate = 1600 - cap;
        byte[] padded = in.length % (rate / 8) == 0 ? in : padTenOne(rate, in);
        long[][] states = byteArrayToStates(padded, cap);
        long[] stcml = new long[25];
        for (long[] st : states) {
            stcml = KeccakProcessor.keccak(KeccakProcessor.xorStates(stcml, st), 1600, 24);
        }

        long[] out = {};
        int offset = 0;
        do {
            out = Arrays.copyOf(out, offset + rate / 64);
            System.arraycopy(stcml, 0, out, offset, rate / 64);
            offset += rate / 64;
            stcml = KeccakProcessor.keccak(stcml, 1600, 24);
        } while (out.length * 64 < bitLen);

        return stateToByteArray(out, bitLen);
    }
    /**
     * Implements the pad10*1 padding scheme.
     * This is used in Keccak to ensure that the input data is a multiple of the rate.
     * The name "pad10*1" comes from the pattern of the padding: it always starts with a '1' bit,
     * is followed by a number of '0' bits, and ends with a '1' bit.
     * Adapted from:
     * - https://github.com/NWc0de/KeccakUtils/blob/master/src/crypto/keccak/KCrypt.java
     *
     * @param rate The rate in bits
     * @param in The input bytes that need padding
     * @return The input bytes with the necessary padding applied
     */
    private static byte[] padTenOne(int rate, byte[] in) {
        int bytesToPad = (rate / 8) - in.length % (rate / 8);
        byte[] padded = new byte[in.length + bytesToPad];
        for (int i = 0; i < in.length + bytesToPad; i++) {
            if (i < in.length) padded[i] = in[i];
            else if (i==in.length + bytesToPad - 1) padded[i] = (byte) 0x80;
            else padded[i] = 0;
        }

        return padded;
    }
    /**
     * Calculates the XOR of two given byte arrays.
     *
     * @param b1 First byte array
     * @param b2 Second byte array
     * @return Byte array after XOR operation
     */
    public static byte[] xorBytes(byte[] b1, byte[] b2) {
        byte[] out = new byte[b1.length];
        for (int i = 0; i < b1.length; i++) {
            out[i] = (byte) (b1[i] ^ b2[i]);
        }
        return out;
    }

    /**
     * Concatenates two given byte arrays.
     *
     * @param b1 First byte array
     * @param b2 Second byte array
     * @return Concatenated byte array
     */
    public static byte[] concat(byte[] b1, byte[] b2) {
        byte[] z = new byte[b1.length + b2.length];
        System.arraycopy(b1,0,z,0,b1.length);
        System.arraycopy(b2,0,z,b1.length,b2.length);
        return z;
    }

    /**
     * Converts the provided byte array into its hexadecimal string representation.
     *
     * @param b Byte array to be converted
     * @return Hexadecimal string representation of the byte array
     */
    public static String bytesToHexString(byte[] b)  {
        int space = 0;

        StringBuilder hex = new StringBuilder();
        for (int i = 0; i < b.length; i++) {
            if(space == 1) {
                hex.append(" ");
                space = 0;
            }

            hex.append(String.format("%02X", b[i]));
            space++;
        }
        return hex.toString();
    }
    /**
     * Converts the provided hexadecimal string into a byte array.
     *
     * @param s Hexadecimal string to be converted
     * @return Byte array representation of the hexadecimal string
     */
    public static byte[] hexStringToBytes(String s) {
        s = s.replaceAll("\\s", "");
        byte[] val = new byte[s.length()/2];
        for (int i = 0; i < val.length; i++) {
            int index = i * 2;
            int j = Integer.parseInt(s.substring(index,index + 2), 16);
            val[i] = (byte) j;
        }
        return val;
    }
    /**
     * Converts the provided state into a byte array.
     *
     * @param state The state to be converted
     * @param bitLen Desired bit length of the output
     * @return Byte array representation of the state
     */
    private static byte[] stateToByteArray(long[] state, int bitLen) {
        if (state.length*64 < bitLen) throw new IllegalArgumentException("State is of insufficient length to produced desired bit length.");
        byte[] out = new byte[bitLen/8];
        int wrdInd = 0;
        while (wrdInd*64 < bitLen) {
            long word = state[wrdInd++];
            int fill = wrdInd*64 > bitLen ? (bitLen - (wrdInd - 1) * 64) / 8 : 8;
            for (int b = 0; b < fill; b++) {
                byte ubt = (byte) (word>>>(8*b) & 0xFF);
                out[(wrdInd - 1)*8 + b] = ubt;
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
        long[][] states = new long[(in.length*8)/(1600-cap)][25];
        int offset = 0;
        for (int i = 0; i < states.length; i++) {
            long[] state = new long[25];
            for (int j = 0; j < (1600-cap)/64; j++) {
                long word = bytesToWord(offset, in);
                state[j] = word;
                offset += 8;
            }

            states[i] = state;
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
        if (in.length < offset+8) throw new IllegalArgumentException("Byte range unreachable, index out of range.");

        long word = 0L;
        for (int i = 0; i < 8; i++) {
            word += (((long)in[offset + i]) & 0xff)<<(8*i);
        }
        return word;
    }
}
