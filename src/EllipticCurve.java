import java.math.BigInteger;

public class EllipticCurve {
    private static final BigInteger p = BigInteger.valueOf(2).pow(448)
            .subtract(BigInteger.valueOf(2).pow(224)).subtract(BigInteger.ONE);
    public static final BigInteger r = BigInteger.valueOf(2).pow(446)
            .subtract(new BigInteger("13818066809895115352007386748515426880336692474882178609894547503885"));
    private static final BigInteger d = BigInteger.valueOf(-39081); // Coefficient for the curve equation
    private static final BigInteger one = BigInteger.ONE;
    private static final BigInteger xG = new BigInteger("8");
    private static final BigInteger yG = new BigInteger("56340020092908815261360962937864138541010268211725856" +
            "6404750214022059686929583319585040850282322731241505930835997382613319689400286258");

    public static EllipticCurvePoint getG() {
        return new EllipticCurvePoint(xG, yG);
    }

    /**
     * Compute a square root of v mod p with a specified least-significant bit
     * if such a root exists.
     *
     * @param v the radiand.
     * @param p the modulus (must satisfy p mod 4 = 3).
     * @param lsb desired least significant bit (ture: 1, false 0).
     * @return a square root r of v mod p with r mod 2 = 1 iff lsb = true
     *          if such a root exists, otherwise null.
     */
    public static BigInteger sqrt(BigInteger v, BigInteger p, boolean lsb) {
        assert (p.testBit(0) && p.testBit(1)); // p = 3 (mod 4)
        if (v.signum() == 0) {
            return BigInteger.ZERO;
        }

        BigInteger r = v.modPow(p.shiftRight(2).add(BigInteger.ONE), p);
        if (r.testBit(0) != lsb) {
            r = p.subtract(r); // correct the lsb
        }
        return (r.multiply(r).subtract(v).mod(p).signum() == 0) ? r : null;
    }

    public static EllipticCurvePoint exponentiation(EllipticCurvePoint G, BigInteger s) {
        EllipticCurvePoint P = G;
        for (int i = s.bitLength() - 2; i >= 0; i--) {
            P = add(P, P);
            if (s.testBit(i)) {
                P = add(P, G);
            }
        }
        return P;
    }

    public static EllipticCurvePoint add(EllipticCurvePoint p1, EllipticCurvePoint p2) {
        BigInteger xDenominator = one.add(d.multiply(p1.getX()).multiply(p2.getX()).
                multiply(p1.getY()).multiply(p2.getY()));
        BigInteger xNumerator = (((p1.getX().multiply(p2.getY())).add(p1.getY().
                multiply(p2.getX()))));
        BigInteger yDenominator = one.subtract(d.multiply(p1.getX().multiply(p2.getX()).
                multiply(p1.getY()).multiply(p2.getY())));
        BigInteger yNumerator = (((p1.getY().multiply(p2.getY())).subtract(p1.getX().
                multiply(p2.getX()))));

        return new EllipticCurvePoint(xNumerator.multiply(xDenominator.modInverse(p)).mod(p),
                yNumerator.multiply(yDenominator.modInverse(p)).mod(p));
    }

}
