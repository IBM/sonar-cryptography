

public class JcaCipherGetInstance3TestFile {

    void test() {
        java.security.Provider[] provider = java.security.Security.getProviders();
        java.security.MessageDigest md;
        if (provider.length > 1) {
            md = java.security.MessageDigest.getInstance("sha-384", provider[0]);
        } else {
            md = java.security.MessageDigest.getInstance("sha-384", "SUN");
        }
    }
}