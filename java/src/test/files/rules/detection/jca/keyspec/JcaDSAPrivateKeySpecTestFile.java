import javax.crypto.SecretKeyFactory;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class JcaDSAPrivateKeySpecTestFile {

    public void test() throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("DSA"); // Noncompliant {{(SecretKey) DSA}}
        factory.generateSecret(spec());
    }

    public KeySpec spec() {
        BigInteger x = new BigInteger("4451685225093714772084598273548424");
        BigInteger p = new BigInteger("4451685225093714772084598273548424");
        BigInteger q = new BigInteger("4451685225093714772084598273548424");
        BigInteger g = new BigInteger("4451685225093714772084598273548424");
        return new DSAPrivateKeySpec(x, p, q, g);
    }
}