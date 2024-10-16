import org.bouncycastle.crypto.engines.GOST3412_2015Engine;
import org.bouncycastle.crypto.modes.G3413CFBBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;

public class BcG3413CFBBlockCipherTestFile {

    public void AESCipherCBCnoPad(byte[] key) {
        GOST3412_2015Engine engine = new GOST3412_2015Engine(); //  Noncompliant {{(BlockCipher) GOST R 34.12-2015))}}
        G3413CFBBlockCipher cipher = new G3413CFBBlockCipher(engine, 128); // Noncompliant {{(BlockCipher) GOST R 34.12-2015))}}
        KeyParameter kp = new KeyParameter(key);
        cipher.init(true, kp);
        return;
    }
}