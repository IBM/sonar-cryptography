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
package com.ibm.plugin.rules.detection.bc.signer;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.OperationMode;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MaskGenerationFunction;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.ProbabilisticSignatureScheme;
import com.ibm.mapper.model.functionality.Sign;
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

class BcPSSSignerTest extends TestBase {
    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile("src/test/files/rules/detection/bc/signer/BcPSSSignerTestFile.java")
                .withChecks(this)
                .withClassPath(BouncyCastleJars.JARS)
                .verifyIssues();
    }

    @Override
    public void asserts(
            int findingId,
            @NotNull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @NotNull List<INode> nodes) {
        /**
         * TODO: Optimally, we shouldn't have these direct detections of engines, as they appear in
         * the depending detection rules
         */
        if (findingId == 0) {
            return;
        }

        /*
         * Detection Store
         */

        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(SignatureContext.class);
        IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
        assertThat(value0).isInstanceOf(ValueAction.class);
        assertThat(value0.asString()).isEqualTo("PSS");

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_1 =
                getStoreOfValueType(OperationMode.class, detectionStore.getChildren());
        assertThat(store_1.getDetectionValues()).hasSize(1);
        assertThat(store_1.getDetectionValueContext()).isInstanceOf(SignatureContext.class);
        IValue<Tree> value0_1 = store_1.getDetectionValues().get(0);
        assertThat(value0_1).isInstanceOf(OperationMode.class);
        assertThat(value0_1.asString()).isEqualTo("1");

        List<DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext>> stores =
                getStoresOfValueType(ValueAction.class, detectionStore.getChildren());
        assertThat(stores).hasSize(3);

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_2 = stores.get(0);
        assertThat(store_2.getDetectionValues()).hasSize(1);
        assertThat(store_2.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        IValue<Tree> value0_2 = store_2.getDetectionValues().get(0);
        assertThat(value0_2).isInstanceOf(ValueAction.class);
        assertThat(value0_2.asString()).isEqualTo("RSA");

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_3 = stores.get(1);
        assertThat(store_3.getDetectionValues()).hasSize(1);
        assertThat(store_3.getDetectionValueContext()).isInstanceOf(DigestContext.class);
        IValue<Tree> value0_3 = store_3.getDetectionValues().get(0);
        assertThat(value0_3).isInstanceOf(ValueAction.class);
        assertThat(value0_3.asString()).isEqualTo("SHA-256");

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_4 = stores.get(2);
        assertThat(store_4.getDetectionValues()).hasSize(1);
        assertThat(store_4.getDetectionValueContext()).isInstanceOf(DigestContext.class);
        IValue<Tree> value0_4 = store_4.getDetectionValues().get(0);
        assertThat(value0_4).isInstanceOf(ValueAction.class);
        assertThat(value0_4.asString()).isEqualTo("SHA-512");

        /*
         * Translation
         */

        assertThat(nodes).hasSize(1);

        // Signature
        INode signatureNode = nodes.get(0);
        assertThat(signatureNode.getKind()).isEqualTo(Signature.class);
        assertThat(signatureNode.getChildren()).hasSize(5);
        assertThat(signatureNode.asString()).isEqualTo("RSA-PSS");

        // Sign under Signature
        INode signNode = signatureNode.getChildren().get(Sign.class);
        assertThat(signNode).isNotNull();
        assertThat(signNode.getChildren()).isEmpty();
        assertThat(signNode.asString()).isEqualTo("SIGN");

        // ProbabilisticSignatureScheme under Signature
        INode probabilisticSignatureSchemeNode =
                signatureNode.getChildren().get(ProbabilisticSignatureScheme.class);
        assertThat(probabilisticSignatureSchemeNode).isNotNull();
        assertThat(probabilisticSignatureSchemeNode.getChildren()).isEmpty();
        assertThat(probabilisticSignatureSchemeNode.asString()).isEqualTo("PSS");

        // MaskGenerationFunction under Signature
        INode maskGenerationFunctionNode =
                signatureNode.getChildren().get(MaskGenerationFunction.class);
        assertThat(maskGenerationFunctionNode).isNotNull();
        assertThat(maskGenerationFunctionNode.getChildren()).isEmpty();
        assertThat(maskGenerationFunctionNode.asString()).isEqualTo("SHA-512");

        // BlockCipher under Signature
        INode blockCipherNode1 = signatureNode.getChildren().get(BlockCipher.class);
        assertThat(blockCipherNode1).isNotNull();
        assertThat(blockCipherNode1.getChildren()).hasSize(1);
        assertThat(blockCipherNode1.asString()).isEqualTo("RSA");

        // MessageDigest under Signature
        INode messageDigestNode = signatureNode.getChildren().get(MessageDigest.class);
        assertThat(messageDigestNode).isNotNull();
        assertThat(messageDigestNode.getChildren()).hasSize(1);
        assertThat(messageDigestNode.asString()).isEqualTo("SHA-256");
    }
}
