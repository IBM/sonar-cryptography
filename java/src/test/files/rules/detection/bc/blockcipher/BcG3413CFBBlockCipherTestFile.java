import org.bouncycastle.crypto.engines.GOST3412_2015Engine;
import org.bouncycastle.crypto.modes.G3413CFBBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;

public class BcG3413CFBBlockCipherTestFile {

    public void AESCipherCBCnoPad(byte[] key) {
        GOST3412_2015Engine engine = new GOST3412_2015Engine(); //  Noncompliant {{GOST3412_2015Engine}}
        G3413CFBBlockCipher cipher = new G3413CFBBlockCipher(engine, 128); // Noncompliant {{G3413CFBBlockCipher}}
        KeyParameter kp = new KeyParameter(key);
        cipher.init(true, kp);
        return;
    }
}