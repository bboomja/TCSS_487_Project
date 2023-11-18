import java.math.BigInteger;

public class EllipticCurvePoint {
    private final BigInteger x;
    private final BigInteger y;

    // Constructor for a point on the curve
    public EllipticCurvePoint(BigInteger x, BigInteger y) {
        this.x = x;
        this.y = y;
    }

    // Getters for x and y
    public BigInteger getX() {
        return x;
    }

    public BigInteger getY() {
        return y;
    }

    // Implement other necessary methods like point negation, etc.
}
