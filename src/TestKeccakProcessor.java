public class TestKeccakProcessor {
    public static void main(String[] args) {
        long[] testValues = {
                0x0123456789ABCDEFL, 0xFEDCBA9876543210L, 0xAABBCCDDEEFF0011L,
                0x0011223344556677L, 0x8899AABBCCDDEEFFL
        };
        int[] rotateValues = {1, 5, 8, 16, 32, 48, 55, 63};

        boolean allMatch = true;

        for (long testValue : testValues) {
            for (int rotateValue : rotateValues) {
                long rotatedUsingOriginal = originalRotateLane64(testValue, rotateValue);
                long rotatedUsingNew = newRotateLane64(testValue, rotateValue);
                if (rotatedUsingOriginal != rotatedUsingNew) {
                    allMatch = false;
                    System.out.println("Mismatch detected for value: " + testValue + " rotate: " + rotateValue);
                }
            }
        }

        if (allMatch) {
            System.out.println("All rotation results match.");
        } else {
            System.out.println("There are mismatches in rotation results.");
        }
    }

    private static long originalRotateLane64(long x, int y) {
        return (x << (y % 64)) | (x >>> (64 - (y % 64)));
    }

    private static long newRotateLane64(long x, int y) {
        return Long.rotateLeft(x, y);
    }
}
