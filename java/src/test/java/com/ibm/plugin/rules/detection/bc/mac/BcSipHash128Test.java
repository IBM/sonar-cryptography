/*
 * SonarQube Cryptography Plugin
 * Copyright (C) 2024 IBM
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to you under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.ibm.plugin.rules.detection.bc.mac;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.MacContext;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.functionality.Digest;
import com.ibm.mapper.model.functionality.Tag;
import com.ibm.plugin.TestBase;
import com.ibm.plugin.rules.detection.bc.BouncyCastleJars;
import java.util.List;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

class BcSipHash128Test extends TestBase {
    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile("src/test/files/rules/detection/bc/mac/BcSipHash128TestFile.java")
                .withChecks(this)
                .withClassPath(BouncyCastleJars.JARS)
                .verifyIssues();
    }

    @Override
    public void asserts(
            int findingId,
            @NotNull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @NotNull List<INode> nodes) {
        /*
         * Detection Store
         */

        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(MacContext.class);
        IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
        assertThat(value0).isInstanceOf(ValueAction.class);
        assertThat(value0.asString()).isEqualTo(findingId == 1 ? "SipHash128" : "SipHash");

        /*
         * Translation
         */

        assertThat(nodes).hasSize(1);

        // Mac
        INode macNode1 = nodes.get(0);
        assertThat(macNode1.getKind()).isEqualTo(Mac.class);
        assertThat(macNode1.getChildren()).hasSize(3);
        assertThat(macNode1.asString()).isEqualTo("SipHash");

        // Tag under Mac
        INode tagNode1 = macNode1.getChildren().get(Tag.class);
        assertThat(tagNode1).isNotNull();
        assertThat(tagNode1.getChildren()).isEmpty();
        assertThat(tagNode1.asString()).isEqualTo("TAG");

        // MessageDigest under Mac
        INode messageDigestNode1 = macNode1.getChildren().get(MessageDigest.class);
        assertThat(messageDigestNode1).isNotNull();
        assertThat(messageDigestNode1.getChildren()).hasSize(findingId == 1 ? 1 : 0);
        assertThat(messageDigestNode1.asString()).isEqualTo("SipHash");

        // Digest under Mac
        INode digestNode1 = macNode1.getChildren().get(Digest.class);
        assertThat(digestNode1).isNotNull();
        assertThat(digestNode1.getChildren()).isEmpty();
        assertThat(digestNode1.asString()).isEqualTo("DIGEST");

        if (findingId == 1) {
            // DigestSize under MessageDigest under Mac
            INode digestSizeNode = messageDigestNode1.getChildren().get(DigestSize.class);
            assertThat(digestSizeNode).isNotNull();
            assertThat(digestSizeNode.getChildren()).isEmpty();
            assertThat(digestSizeNode.asString()).isEqualTo("128");
        }
    }
}
