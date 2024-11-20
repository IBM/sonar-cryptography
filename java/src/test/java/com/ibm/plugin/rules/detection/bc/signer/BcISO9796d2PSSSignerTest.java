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
import com.ibm.engine.model.SaltSize;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.ProbabilisticSignatureScheme;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.SaltLength;
import com.ibm.mapper.model.functionality.Digest;
import com.ibm.mapper.model.functionality.Sign;
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

class BcISO9796d2PSSSignerTest extends TestBase {
    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile(
                        "src/test/files/rules/detection/bc/signer/BcISO9796d2PSSSignerTestFile.java")
                .withChecks(this)
                .withClassPath(BouncyCastleJars.JARS)
                .verifyIssues();
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes) {

        if (findingId == 0 || findingId == 1) {
            return;
        }

        /*
         * Detection Store
         */

        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(SignatureContext.class);
        IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
        assertThat(value0).isInstanceOf(ValueAction.class);
        assertThat(value0.asString()).isEqualTo("ISO9796d2PSSSigner");

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_1 =
                getStoreOfValueType(OperationMode.class, detectionStore.getChildren());
        assertThat(store_1.getDetectionValues()).hasSize(1);
        assertThat(store_1.getDetectionValueContext()).isInstanceOf(SignatureContext.class);
        IValue<Tree> value0_1 = store_1.getDetectionValues().get(0);
        assertThat(value0_1).isInstanceOf(OperationMode.class);
        assertThat(value0_1.asString()).isEqualTo("1");

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_2 =
                getStoreOfValueType(SaltSize.class, detectionStore.getChildren());
        assertThat(store_2.getDetectionValues()).hasSize(1);
        assertThat(store_2.getDetectionValueContext()).isInstanceOf(SignatureContext.class);
        IValue<Tree> value0_2 = store_2.getDetectionValues().get(0);
        assertThat(value0_2).isInstanceOf(SaltSize.class);
        assertThat(value0_2.asString()).isEqualTo("256");

        List<DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext>> stores =
                getStoresOfValueType(ValueAction.class, detectionStore.getChildren());

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_3 = stores.get(0);
        assertThat(store_3.getDetectionValues()).hasSize(1);
        assertThat(store_3.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        IValue<Tree> value0_3 = store_3.getDetectionValues().get(0);
        assertThat(value0_3).isInstanceOf(ValueAction.class);
        assertThat(value0_3.asString()).isEqualTo("ISO9796d1Encoding");

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_3_1 =
                getStoreOfValueType(ValueAction.class, store_3.getChildren());
        assertThat(store_3_1.getDetectionValues()).hasSize(1);
        assertThat(store_3_1.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        IValue<Tree> value0_3_1 = store_3_1.getDetectionValues().get(0);
        assertThat(value0_3_1).isInstanceOf(ValueAction.class);
        assertThat(value0_3_1.asString()).isEqualTo("RSAEngine");

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_4 = stores.get(1);
        assertThat(store_4.getDetectionValues()).hasSize(1);
        assertThat(store_4.getDetectionValueContext()).isInstanceOf(DigestContext.class);
        IValue<Tree> value0_4 = store_4.getDetectionValues().get(0);
        assertThat(value0_4).isInstanceOf(ValueAction.class);
        assertThat(value0_4.asString()).isEqualTo("SHA256Digest");

        /*
         * Translation
         */

        assertThat(nodes).hasSize(1);

        // ProbabilisticSignatureScheme
        INode probabilisticSignatureSchemeNode = nodes.get(0);
        assertThat(probabilisticSignatureSchemeNode.getKind())
                .isEqualTo(ProbabilisticSignatureScheme.class);
        assertThat(probabilisticSignatureSchemeNode.getChildren()).hasSize(4);
        assertThat(probabilisticSignatureSchemeNode.asString()).isEqualTo("ISO 9796-PSS");

        // Sign under ProbabilisticSignatureScheme
        INode signNode = probabilisticSignatureSchemeNode.getChildren().get(Sign.class);
        assertThat(signNode).isNotNull();
        assertThat(signNode.getChildren()).isEmpty();
        assertThat(signNode.asString()).isEqualTo("SIGN");

        // MessageDigest under ProbabilisticSignatureScheme
        INode messageDigestNode =
                probabilisticSignatureSchemeNode.getChildren().get(MessageDigest.class);
        assertThat(messageDigestNode).isNotNull();
        assertThat(messageDigestNode.getChildren()).hasSize(4);
        assertThat(messageDigestNode.asString()).isEqualTo("SHA256");

        // BlockSize under MessageDigest under ProbabilisticSignatureScheme
        INode blockSizeNode = messageDigestNode.getChildren().get(BlockSize.class);
        assertThat(blockSizeNode).isNotNull();
        assertThat(blockSizeNode.getChildren()).isEmpty();
        assertThat(blockSizeNode.asString()).isEqualTo("512");

        // Oid under MessageDigest under ProbabilisticSignatureScheme
        INode oidNode2 = messageDigestNode.getChildren().get(Oid.class);
        assertThat(oidNode2).isNotNull();
        assertThat(oidNode2.getChildren()).isEmpty();
        assertThat(oidNode2.asString()).isEqualTo("2.16.840.1.101.3.4.2.1");

        // DigestSize under MessageDigest under ProbabilisticSignatureScheme
        INode digestSizeNode = messageDigestNode.getChildren().get(DigestSize.class);
        assertThat(digestSizeNode).isNotNull();
        assertThat(digestSizeNode.getChildren()).isEmpty();
        assertThat(digestSizeNode.asString()).isEqualTo("256");

        // Digest under MessageDigest under ProbabilisticSignatureScheme
        INode digestNode = messageDigestNode.getChildren().get(Digest.class);
        assertThat(digestNode).isNotNull();
        assertThat(digestNode.getChildren()).isEmpty();
        assertThat(digestNode.asString()).isEqualTo("DIGEST");

        // SaltLength under ProbabilisticSignatureScheme
        INode saltLengthNode = probabilisticSignatureSchemeNode.getChildren().get(SaltLength.class);
        assertThat(saltLengthNode).isNotNull();
        assertThat(saltLengthNode.getChildren()).isEmpty();
        assertThat(saltLengthNode.asString()).isEqualTo("256");

        // PublicKeyEncryption under ProbabilisticSignatureScheme
        INode publicKeyEncryptionNode2 =
                probabilisticSignatureSchemeNode.getChildren().get(PublicKeyEncryption.class);
        assertThat(publicKeyEncryptionNode2).isNotNull();
        assertThat(publicKeyEncryptionNode2.getChildren()).hasSize(2);
        assertThat(publicKeyEncryptionNode2.asString()).isEqualTo("RSA");

        // Padding under PublicKeyEncryption under ProbabilisticSignatureScheme
        INode paddingNode1 = publicKeyEncryptionNode2.getChildren().get(Padding.class);
        assertThat(paddingNode1).isNotNull();
        assertThat(paddingNode1.getChildren()).isEmpty();
        assertThat(paddingNode1.asString()).isEqualTo("ISO 9796");

        // Oid under PublicKeyEncryption under ProbabilisticSignatureScheme
        INode oidNode3 = publicKeyEncryptionNode2.getChildren().get(Oid.class);
        assertThat(oidNode3).isNotNull();
        assertThat(oidNode3.getChildren()).isEmpty();
        assertThat(oidNode3.asString()).isEqualTo("1.2.840.113549.1.1.1");
    }
}
