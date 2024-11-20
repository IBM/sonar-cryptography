import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

public class BcPKCS1EncodingTestFile {

    public byte[] encryptCEK(final RSAPublicKey pub, final SecretKey cek)
    throws RuntimeException {
        try {
            AsymmetricBlockCipher engine = new RSAEngine(); // Noncompliant {{(PublicKeyEncryption) RSA}}

            PKCS1Encoding cipher = new PKCS1Encoding(engine); // Noncompliant {{(PublicKeyEncryption) RSA}}

            BigInteger mod = pub.getModulus();
            BigInteger exp = pub.getPublicExponent();
            RSAKeyParameters keyParams = new RSAKeyParameters(false, mod, exp);
            cipher.init(true, keyParams);

            // int inputBlockSize = cipher.getInputBlockSize();
            // int outputBlockSize = cipher.getOutputBlockSize();

            byte[] keyBytes = cek.getEncoded();

            return cipher.processBlock(keyBytes, 0, keyBytes.length);

        } catch (Exception e) {
            // org.bouncycastle.crypto.InvalidCipherTextException
            throw new RuntimeException(e);
        }
    }
}
