import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;

public class BcMLDSASignerTestFile {

    void test() {
        MLDSASigner signer = new MLDSASigner(); // Noncompliant {{(Signature) ML-DSA-44}}

        signer.init(true, new MLDSAKeyParameters(true, MLDSAParameters.ml_dsa_44));
    }
}