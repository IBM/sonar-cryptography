import javax.crypto.SecretKeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.lang.String;

public class ResolveFunctionAsParameterAndArgumentTestFile {

    public void test1() throws NoSuchAlgorithmException, InvalidKeySpecException {
        String temp = algorithm("RSA"); // Noncompliant {{(SecretKey) RSA}}
        SecretKeyFactory factory = SecretKeyFactory.getInstance(temp);
    }

    public void test2() throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm("RSA"));  // Noncompliant {{(SecretKey) RSA}}
    }

    public String algorithm(String alg) {
        return alg;
    }
}