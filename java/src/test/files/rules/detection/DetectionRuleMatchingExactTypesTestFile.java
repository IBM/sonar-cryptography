public class DetectionRuleMatchingExactTypesTestFile {

    void test() {
        final Object obj = new Object();
        obj.equals(new String("test")); // Noncompliant {{value}}
    }

    void test2() {
        final String str = new String();
        str.equals(new String("test"));
    }
}