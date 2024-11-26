package com.ibm.plugin.rules.issues;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.TestBase;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

import javax.annotation.Nonnull;
import java.util.List;


class ClientEncryptionJavaDuplicatedRSADetectionTest extends TestBase {

    @Test
    @Disabled
    void test() {
        CheckVerifier.newVerifier()
                .onFile("src/test/files/rules/issues/ClientEncryptionJavaDuplicatedRSADetectionTestFile.java")
                .withChecks(this)
                .verifyIssues();
    }

    @Override
    public void asserts(int findingId, @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore, @Nonnull List<INode> nodes) {

    }
}
