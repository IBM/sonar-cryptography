import java.security.SecureRandom;

public class JcaSecureRandomTestFile {

    public void test() {
        byte[] seed = "1245".getBytes();
        SecureRandom random = new SecureRandom(seed);
    }

}