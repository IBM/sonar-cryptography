import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.G3413CFBBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;

public class DuplicateDependingRulesTestFile {

    public void AESCipherCBCnoPad(byte[] key) {
        AESEngine engine = AESEngine.newInstance(); //  Noncompliant {{AES}}

        G3413CFBBlockCipher cipher = new G3413CFBBlockCipher(engine, 128); // Noncompliant {{GOST R 34.12-2015|CFB}}

        cipher.init(true, new KeyParameter(key));
    }
}