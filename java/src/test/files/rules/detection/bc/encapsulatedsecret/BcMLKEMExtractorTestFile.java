import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class BcMLKEMExtractorTestFile {

    void test() throws KeyManagementException, NoSuchAlgorithmException {
        // Specify mlkem parameters
        byte[] bytes = new byte[2];
        MLKEMPrivateKeyParameters params = new MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_512, bytes);

        // Initialize the key generator
        MLKEMExtractor mlkemExtractor = new MLKEMExtractor(params);  // Noncompliant {{(KeyEncapsulationMechanism) ML-KEM-512}}
    }
}