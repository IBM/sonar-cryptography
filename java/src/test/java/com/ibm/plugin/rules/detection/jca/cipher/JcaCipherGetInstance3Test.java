package com.ibm.plugin.rules.detection.jca.cipher;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.TestBase;
import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

import javax.annotation.Nonnull;
import java.util.List;

class JcaCipherGetInstance3Test extends TestBase {

    protected JcaCipherGetInstance3Test() {
        super(JcaCipherGetInstance.rules());
    }

    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile(
                        "src/test/files/rules/detection/jca/cipher/JcaCipherGetInstance3TestFile.java")
                .withChecks(this)
                .verifyIssues();
    }

    @Override
    public void asserts(int findingId, @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore, @Nonnull List<INode> nodes) {

    }
}
