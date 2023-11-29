import java.math.BigInteger;

public class EllipticCurvePoint {
    private BigInteger x;
    private BigInteger y;

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

   public void setX(BigInteger x) {
        this.x = x;
   }

   public void setY(BigInteger y) {
        this.y = y;
   }

   @Override
   public String toString() {
        String s = "";
        s = s + x.toString() + "\n" + y.toString();
        return s;
   }


}
