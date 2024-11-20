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
package com.ibm.plugin.rules.issues;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MaskGenerationFunction;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.plugin.TestBase;
import com.ibm.plugin.rules.detection.bc.BouncyCastleJars;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

class DuplicateParameterFindingsTest extends TestBase {

    /**
     * This test is associated to the detection rule CONSTRUCTOR_4 of `OAEPEncoding`. This
     * constructor takes 2 different hashes (`org.bouncycastle.crypto.Digest`). The 1st is
     * `SHA3Digest()` with context `DigestContext<NONE>`. The 2nd is `SHA512Digest()` with context
     * `DigestContext<MGF1>`.
     *
     * <p>The issue is here at the level of the detection store: the two digests are detected twice,
     * each with the two possible contexts, which is not expected and makes impossible to
     * distinguish the two hashes from their contexts.
     */
    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile("src/test/files/rules/issues/DuplicateParameterFindingsTestFile.java")
                .withChecks(this)
                .withClassPath(BouncyCastleJars.JARS)
                .verifyIssues();
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes) {
        if (findingId == 0) {
            return;
        }

        /*
         * Detection Store
         */

        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
        assertThat(value0).isInstanceOf(ValueAction.class);
        assertThat(value0.asString()).isEqualTo("OAEPEncoding");

        List<DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext>> valueActionStores =
                getStoresOfValueType(ValueAction.class, detectionStore.getChildren());

        /* We expect only 3 ValueAction under OAEP, but there are currently 5 (2 duplicates with incorrect context) */
        assertThat(valueActionStores).hasSize(3);

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_2 =
                valueActionStores.get(0);
        assertThat(store_2.getDetectionValues()).hasSize(1);
        assertThat(store_2.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        IValue<Tree> value0_2 = store_2.getDetectionValues().get(0);
        assertThat(value0_2).isInstanceOf(ValueAction.class);
        assertThat(value0_2.asString()).isEqualTo("RSAEngine");

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_3 =
                valueActionStores.get(1);
        assertThat(store_3.getDetectionValues()).hasSize(1);
        assertThat(store_3.getDetectionValueContext()).isInstanceOf(DigestContext.class);
        IValue<Tree> value0_4 = store_3.getDetectionValues().get(0);
        assertThat(value0_4).isInstanceOf(ValueAction.class);
        assertThat(value0_4.asString()).isEqualTo("SHA3Digest");

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_4 =
                valueActionStores.get(2);
        assertThat(store_4.getDetectionValues()).hasSize(1);
        assertThat(store_4.getDetectionValueContext()).isInstanceOf(DigestContext.class);
        IValue<Tree> value0_5 = store_4.getDetectionValues().get(0);
        assertThat(value0_5).isInstanceOf(ValueAction.class);
        assertThat(value0_5.asString()).isEqualTo("SHA512Digest");

        /*
         * Translation
         */

        assertThat(nodes).hasSize(1);

        // PublicKeyEncryption
        INode publicKeyEncryptionNode1 = nodes.get(0);
        assertThat(publicKeyEncryptionNode1.getKind()).isEqualTo(PublicKeyEncryption.class);
        assertThat(publicKeyEncryptionNode1.getChildren()).hasSize(4);
        assertThat(publicKeyEncryptionNode1.asString()).isEqualTo("RSA-OAEP");

        // MessageDigest under PublicKeyEncryption
        INode messageDigestNode = publicKeyEncryptionNode1.getChildren().get(MessageDigest.class);
        assertThat(messageDigestNode).isNotNull();
        assertThat(messageDigestNode.getChildren()).hasSize(1);
        assertThat(messageDigestNode.asString()).isEqualTo("SHA3");

        // OptimalAsymmetricEncryptionPadding under PublicKeyEncryption
        INode optimalAsymmetricEncryptionPaddingNode =
                publicKeyEncryptionNode1.getChildren().get(Padding.class);
        assertThat(optimalAsymmetricEncryptionPaddingNode).isNotNull();
        assertThat(optimalAsymmetricEncryptionPaddingNode.getChildren()).isEmpty();
        assertThat(optimalAsymmetricEncryptionPaddingNode.asString()).isEqualTo("OAEP");

        // MaskGenerationFunction under PublicKeyEncryption
        INode maskGenerationFunctionNode =
                publicKeyEncryptionNode1.getChildren().get(MaskGenerationFunction.class);
        assertThat(maskGenerationFunctionNode).isNotNull();
        assertThat(maskGenerationFunctionNode.getChildren()).hasSize(2);
        assertThat(maskGenerationFunctionNode.asString()).isEqualTo("MGF1");

        // MessageDigest under MaskGenerationFunction under PublicKeyEncryption
        INode messageDigestNode1 =
                maskGenerationFunctionNode.getChildren().get(MessageDigest.class);
        assertThat(messageDigestNode1).isNotNull();
        assertThat(messageDigestNode1.getChildren()).hasSize(4);
        assertThat(messageDigestNode1.asString()).isEqualTo("SHA512");
    }
}
