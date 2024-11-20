import org.bouncycastle.pqc.crypto.bike.BIKEKEMExtractor;
import org.bouncycastle.pqc.crypto.bike.BIKEParameters;
import org.bouncycastle.pqc.crypto.bike.BIKEPrivateKeyParameters;

public class BcBIKEKEMExtractorTestFile {

    public static void test() {
        // Create a BIKEPrivateKeyParameters object named privParams
        BIKEPrivateKeyParameters privParams =
                new BIKEPrivateKeyParameters(BIKEParameters.bike128, null, null, null);

        // Instantiate the BIKEKEMExtractor
        BIKEKEMExtractor extractor = new BIKEKEMExtractor(privParams); // Noncompliant {{(KeyEncapsulationMechanism) BIKE}}

        // Extract the shared secret key using the private key parameters
        byte[] sharedSecret = extractor.extractSecret(null);

        // ...
    }
}
