package com.ibm.example; 

public class DuplicateDependingRules2TestFile {

    public class ExampleObject {
        ExampleObject(String exampleParam) {}

        public void init(String initParam) {}
    }

    public void test() {
        ExampleObject exampleObject = new ExampleObject("ExampleParamValue"); // Noncompliant {{ExampleObject}}
        exampleObject.init("InitParamValue");
    }
}
