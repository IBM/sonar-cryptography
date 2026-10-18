using System.Security.Cryptography;

public class ProbeCSharpAliasReassignmentTestFile
{
    public void TestAliasReassignment()
    {
        var first = Aes.Create();
        var second = TripleDES.Create();
        var alias = first;
        alias = second;
        alias.Mode = CipherMode.CBC;
    }
}
