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
package com.ibm.plugin.rules.detection.jca.signature;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.SaltSize;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.mapper.model.*;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

class JcaSignatureSetParameterTest extends TestBase {

    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile(
                        "src/test/files/rules/detection/jca/signature/JcaSignatureSetParameterTestFile.java")
                .withChecks(this)
                .verifyIssues();
    }

    /**
     * DEBUG [detectionStore] (SignatureContext, Algorithm) RSASSA-PSS DEBUG [detectionStore] └─
     * (SignatureContext, SaltSize<bit>) 160 DEBUG [translation] (Signature) RSASSA-PSS DEBUG
     * [translation] └─ (Algorithm) RSA DEBUG [translation] └─ (Oid) 1.2.840.113549.1.1.1 DEBUG
     * [translation] └─ (KeyLength) 2048 DEBUG [translation] └─ (Oid) 1.2.840.113549.1.1.10 DEBUG
     * [translation] └─ (MaskGenerationFunction) MGF1 DEBUG [translation] └─ (MessageDigest) SHA-1
     * DEBUG [translation] └─ (BlockSize) 512 DEBUG [translation] └─ (KeyLength) 512 DEBUG
     * [translation] └─ (DigestSize) 160 DEBUG [translation] └─ (ProbabilisticSignatureScheme) PSS
     * DEBUG [translation] └─ (SaltLength) 160 DEBUG [translation] └─ (MessageDigest) SHA-1 DEBUG
     * [translation] └─ (BlockSize) 512 DEBUG [translation] └─ (KeyLength) 512 DEBUG [translation]
     * └─ (DigestSize) 160
     */
    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes) {
        /*
         * Detection Store
         */
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        IValue<Tree> value = detectionStore.getDetectionValues().get(0);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(SignatureContext.class);
        assertThat(value).isInstanceOf(Algorithm.class);
        assertThat(value.asString()).isEqualTo("RSASSA-PSS");

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store =
                getStoreOfValueType(SaltSize.class, detectionStore.getChildren());
        assertThat(store).isNotNull();
        assertThat(store.getDetectionValueContext()).isInstanceOf(SignatureContext.class);
        assertThat(store.getDetectionValues()).hasSize(1);
        value = store.getDetectionValues().get(0);
        assertThat(value).isInstanceOf(SaltSize.class);
        assertThat(value.asString()).isEqualTo("160");
        /*
         * Translation
         */
        assertThat(nodes).hasSize(1);
        INode node = nodes.get(0);
        assertThat(node).isInstanceOf(Signature.class);
        assertThat(node.asString()).isEqualTo("RSASSA-PSS");

        INode algorithm = node.getChildren().get(com.ibm.mapper.model.Algorithm.class);
        assertThat(algorithm).isNotNull();
        assertThat(algorithm.asString()).isEqualTo("RSA");
        INode oid = algorithm.getChildren().get(Oid.class);
        assertThat(oid).isNotNull();
        assertThat(oid.asString()).isEqualTo("1.2.840.113549.1.1.1");
        INode keyLength = algorithm.getChildren().get(KeyLength.class);
        assertThat(keyLength).isNotNull();
        assertThat(keyLength.asString()).isEqualTo("2048");

        oid = node.getChildren().get(Oid.class);
        assertThat(oid).isNotNull();
        assertThat(oid.asString()).isEqualTo("1.2.840.113549.1.1.10");

        INode mgf1 = node.getChildren().get(MaskGenerationFunction.class);
        assertThat(mgf1).isNotNull();
        assertThat(mgf1.asString()).isEqualTo("MGF1");
        INode md = mgf1.getChildren().get(MessageDigest.class);
        assertThat(md).isNotNull();
        assertThat(md.asString()).isEqualTo("SHA-1");

        INode pss = node.getChildren().get(ProbabilisticSignatureScheme.class);
        assertThat(pss).isNotNull();
        assertThat(pss.asString()).isEqualTo("PSS");

        INode salt = node.getChildren().get(SaltLength.class);
        assertThat(salt).isNotNull();
        assertThat(salt.asString()).isEqualTo("160");

        md = node.getChildren().get(MessageDigest.class);
        assertThat(md).isNotNull();
        assertThat(md.asString()).isEqualTo("SHA-1");
    }
}
