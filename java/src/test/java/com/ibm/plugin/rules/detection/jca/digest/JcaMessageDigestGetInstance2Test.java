package com.ibm.plugin.rules.detection.jca.digest;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.functionality.Digest;
import com.ibm.plugin.TestBase;
import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

import javax.annotation.Nonnull;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class JcaMessageDigestGetInstance2Test extends TestBase {

    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile(
                        "src/test/files/rules/detection/jca/digest/JcaMessageDigestGetInstance2TestFile.java")
                .withChecks(this)
                .verifyIssues();
    }

    @Override
    public void asserts(int findingId, @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore, @Nonnull List<INode> nodes) {
        /*
         * Detection Store
         */

        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(DigestContext.class);
        IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
        assertThat(value0).isInstanceOf(Algorithm.class);
        assertThat(value0.asString()).isEqualTo("sha-384");


        /*
         * Translation
         */

        assertThat(nodes).hasSize(1);

// MessageDigest
        INode messageDigestNode1 = nodes.get(0);
        assertThat(messageDigestNode1.getKind()).isEqualTo(MessageDigest.class);
        assertThat(messageDigestNode1.getChildren()).hasSize(4);
        assertThat(messageDigestNode1.asString()).isEqualTo("SHA384");

// Oid under MessageDigest
        INode oidNode1 = messageDigestNode1.getChildren().get(Oid.class);
        assertThat(oidNode1).isNotNull();
        assertThat(oidNode1.getChildren()).isEmpty();
        assertThat(oidNode1.asString()).isEqualTo("2.16.840.1.101.3.4.2.2");

// Digest under MessageDigest
        INode digestNode1 = messageDigestNode1.getChildren().get(Digest.class);
        assertThat(digestNode1).isNotNull();
        assertThat(digestNode1.getChildren()).isEmpty();
        assertThat(digestNode1.asString()).isEqualTo("DIGEST");

// DigestSize under MessageDigest
        INode digestSizeNode1 = messageDigestNode1.getChildren().get(DigestSize.class);
        assertThat(digestSizeNode1).isNotNull();
        assertThat(digestSizeNode1.getChildren()).isEmpty();
        assertThat(digestSizeNode1.asString()).isEqualTo("384");

// BlockSize under MessageDigest
        INode blockSizeNode1 = messageDigestNode1.getChildren().get(BlockSize.class);
        assertThat(blockSizeNode1).isNotNull();
        assertThat(blockSizeNode1.getChildren()).isEmpty();
        assertThat(blockSizeNode1.asString()).isEqualTo("1024");
    }
}
