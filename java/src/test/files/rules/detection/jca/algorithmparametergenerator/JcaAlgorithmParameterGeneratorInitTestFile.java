import java.security.AlgorithmParameterGenerator;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

public class JcaAlgorithmParameterGeneratorInitTestFile {

    void test() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DiffieHellman"); // Noncompliant {{DiffieHellman}}
        paramGen.init(2048);
    }
}