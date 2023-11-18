import java.math.BigInteger;

public class EllipticCurve {
    private static final BigInteger p = BigInteger.valueOf(2).pow(448)
            .subtract(BigInteger.valueOf(2).pow(224)).subtract(BigInteger.ONE);
    private static final BigInteger r = BigInteger.valueOf(2).pow(446)
            .subtract(new BigInteger("13818066809895115352007386748515426880336692474882178609894547503885"));


}
