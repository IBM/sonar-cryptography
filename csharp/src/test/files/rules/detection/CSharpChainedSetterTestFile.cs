using System.Security.Cryptography;
using System.Security.Cryptography.Xml;

public class CSharpChainedSetterTest {

    // `Options` is another object, so its KeySize is not the key size of rsa
    public void TestChainNotAttributedToVariable() {
        var rsa = RSA.Create(); // Noncompliant
        rsa.Options.KeySize = 4096;
    }

    // the single-level setter keeps attaching to the variable
    public void TestSingleLevelStillAttributed() {
        var rsa = RSA.Create(); // Noncompliant
        rsa.KeySize = 2048;
    }

    // a deeper chain is converted too
    public void TestDeepChain(SignedXml signedXml) {
        signedXml.Outer.Inner.DigestMethod = SignedXml.XmlDsigSHA256Url; // Noncompliant
    }

    // an index inside the chain: the target is not a plain a.b.c path, so no setter
    public void TestIndexedChain(SignedInfo info) {
        info.References[0].DigestMethod = SignedXml.XmlDsigSHA384Url;
    }
}
