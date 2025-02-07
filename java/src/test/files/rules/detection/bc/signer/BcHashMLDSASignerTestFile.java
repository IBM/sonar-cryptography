import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;

class BcHashMLDSASignerTestFile {

    void test(){
        MLDSASigner signer = new MLDSASigner(); // Noncompliant {{(Signature) SHA512withML-DSA-44}}
        signer.init(true, new MLDSAKeyParameters(true, MLDSAParameters.ml_dsa_44_with_sha512));
    }
}