import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;

public class BcECDHBasicAgreementTestFile {

    public static void test() {
        // Create a key pair generator
        KeyPairGenerator keyPairGen = null; // Add this line
        try {
            keyPairGen = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME); // Noncompliant {{(Key) EC}}
            keyPairGen.initialize(256);
        } catch (Exception e) {
            e.printStackTrace();
        }

        // Generate key pair
        KeyPair keyPair = keyPairGen.generateKeyPair();

        // Extract private key
        BCECPrivateKey privKey = (BCECPrivateKey) keyPair.getPrivate();

        // Create a curve parameter specification
        ECParameterSpec ecSpec = privKey.getParameters();
        ECDomainParameters CURVE =
                new ECDomainParameters(
                        ecSpec.getCurve(), ecSpec.getG(), ecSpec.getN(), ecSpec.getH());
        // Initialize agreement with private key
        final ECDHBasicAgreement agreement = new ECDHBasicAgreement(); // Noncompliant {{(KeyAgreement) ECDH}}
        agreement.init(new ECPrivateKeyParameters(privKey.getD(), CURVE));

        // Initialize the ECPoint (use inifinity here for simpler demo code)
        ECPoint otherParty = CURVE.getCurve().getInfinity();

        // Calculate agreement with other party's public key
        BigInteger agreementValue =
                agreement.calculateAgreement(new ECPublicKeyParameters(otherParty, CURVE));

        // Do something with agreement value...
    }
}
