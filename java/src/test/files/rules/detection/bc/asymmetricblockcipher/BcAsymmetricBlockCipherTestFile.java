import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.encodings.ISO9796d1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;

public class BcAsymmetricBlockCipherTestFile {

    public byte[] encryptCEK(final RSAPublicKey pub, final SecretKey cek)
    throws RuntimeException {
        try {
            AsymmetricBlockCipher cipher = new RSAEngine(); // Noncompliant {{(PublicKeyEncryption) RSA}}

            BigInteger mod = pub.getModulus();
            BigInteger exp = pub.getPublicExponent();
            RSAKeyParameters keyParams = new RSAKeyParameters(false, mod, exp);
            cipher.init(true, keyParams);

            byte[] keyBytes = cek.getEncoded();

            return cipher.processBlock(keyBytes, 0, keyBytes.length);

        } catch (Exception e) {
            // org.bouncycastle.crypto.InvalidCipherTextException
            throw new RuntimeException(e);
        }
    }
}
