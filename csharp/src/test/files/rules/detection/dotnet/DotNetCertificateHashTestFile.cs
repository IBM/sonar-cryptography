using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

public class DotNetCertificateHashTest {

    // --- the digest is named in the argument ------------------------------------------------

    public byte[] TestGetCertHash(X509Certificate2 cert) {
        return cert.GetCertHash(HashAlgorithmName.SHA256);
    }

    public string TestGetCertHashString(X509Certificate2 cert) {
        return cert.GetCertHashString(HashAlgorithmName.SHA384);
    }

    public bool TestTryGetCertHash(X509Certificate2 cert, Span<byte> buffer) {
        return cert.TryGetCertHash(HashAlgorithmName.SHA512, buffer, out int written);
    }

    public byte[] TestNamedArgument(X509Certificate2 cert) {
        return cert.GetCertHash(hashAlgorithm: HashAlgorithmName.SHA256);
    }

    // --- a weak digest named explicitly is reported as written --------------------------------

    public byte[] TestExplicitSha1(X509Certificate2 cert) {
        return cert.GetCertHash(HashAlgorithmName.SHA1);
    }

    // --- no argument: the SHA-1 thumbprint ---------------------------------------------------

    public byte[] TestGetCertHashDefault(X509Certificate2 cert) {
        return cert.GetCertHash();
    }

    public string TestGetCertHashStringDefault(X509Certificate2 cert) {
        return cert.GetCertHashString();
    }

    // --- the digest is only known to the caller: nothing may be reported ---------------------

    public byte[] TestDigestNotKnown(X509Certificate2 cert, HashAlgorithmName algorithm) {
        return cert.GetCertHash(algorithm);
    }
}
