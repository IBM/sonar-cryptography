import java.security.SecureRandom;

public class SecureRandomGetInstanceTestFile {

    public void test() {
        byte[] seed = "1245".getBytes();
        SecureRandom random = new SecureRandom(seed);
    }

}