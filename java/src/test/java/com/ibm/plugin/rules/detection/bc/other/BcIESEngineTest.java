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
package com.ibm.plugin.rules.detection.bc.other;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.MacContext;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.KeyDerivationFunction;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.TagLength;
import com.ibm.mapper.model.functionality.Digest;
import com.ibm.mapper.model.functionality.Tag;
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

class BcIESEngineTest extends TestBase {
    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile("src/test/files/rules/detection/bc/other/BcIESEngineTestFile.java")
                .withChecks(this)
                .withClassPath(BouncyCastleJars.JARS)
                .verifyIssues();
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes) {
        if (findingId == 0 || findingId == 1 || findingId == 2) {
            return;
        }

        /*
         * Detection Store
         */

        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
        assertThat(value0).isInstanceOf(ValueAction.class);
        assertThat(value0.asString()).isEqualTo("IESEngine");

        List<DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext>> stores =
                getStoresOfValueType(ValueAction.class, detectionStore.getChildren());

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_1 = stores.get(0);
        assertThat(store_1.getDetectionValues()).hasSize(1);
        assertThat(store_1.getDetectionValueContext()).isInstanceOf(KeyContext.class);
        IValue<Tree> value0_1 = store_1.getDetectionValues().get(0);
        assertThat(value0_1).isInstanceOf(ValueAction.class);
        assertThat(value0_1.asString()).isEqualTo("ECDHBasicAgreement");

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_2 = stores.get(1);
        assertThat(store_2.getDetectionValues()).hasSize(1);
        assertThat(store_2.getDetectionValueContext()).isInstanceOf(KeyContext.class);
        IValue<Tree> value0_2 = store_2.getDetectionValues().get(0);
        assertThat(value0_2).isInstanceOf(ValueAction.class);
        assertThat(value0_2.asString()).isEqualTo("KDF1BytesGenerator");

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_2_1 =
                getStoreOfValueType(ValueAction.class, store_2.getChildren());
        assertThat(store_2_1.getDetectionValues()).hasSize(1);
        assertThat(store_2_1.getDetectionValueContext()).isInstanceOf(DigestContext.class);
        IValue<Tree> value0_2_1 = store_2_1.getDetectionValues().get(0);
        assertThat(value0_2_1).isInstanceOf(ValueAction.class);
        assertThat(value0_2_1.asString()).isEqualTo("SHA256Digest");

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_3 = stores.get(2);
        assertThat(store_3.getDetectionValues()).hasSize(1);
        assertThat(store_3.getDetectionValueContext()).isInstanceOf(MacContext.class);
        IValue<Tree> value0_3 = store_3.getDetectionValues().get(0);
        assertThat(value0_3).isInstanceOf(ValueAction.class);
        assertThat(value0_3.asString()).isEqualTo("HMac");

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_3_1 =
                getStoreOfValueType(ValueAction.class, store_3.getChildren());
        assertThat(store_3_1.getDetectionValues()).hasSize(1);
        assertThat(store_3_1.getDetectionValueContext()).isInstanceOf(DigestContext.class);
        IValue<Tree> value0_3_1 = store_3_1.getDetectionValues().get(0);
        assertThat(value0_3_1).isInstanceOf(ValueAction.class);
        assertThat(value0_3_1.asString()).isEqualTo("SHA512Digest");

        /*
         * Translation
         */

        assertThat(nodes).hasSize(1);

        // PublicKeyEncryption
        INode publicKeyEncryptionNode = nodes.get(0);
        assertThat(publicKeyEncryptionNode.getKind()).isEqualTo(PublicKeyEncryption.class);
        assertThat(publicKeyEncryptionNode.getChildren()).hasSize(3);
        assertThat(publicKeyEncryptionNode.asString()).isEqualTo("IES");

        // Mac under PublicKeyEncryption
        INode macNode1 = publicKeyEncryptionNode.getChildren().get(Mac.class);
        assertThat(macNode1).isNotNull();
        assertThat(macNode1.getChildren()).hasSize(3);
        assertThat(macNode1.asString()).isEqualTo("HMAC-SHA512");

        // Tag under Mac under PublicKeyEncryption
        INode tagNode1 = macNode1.getChildren().get(Tag.class);
        assertThat(tagNode1).isNotNull();
        assertThat(tagNode1.getChildren()).isEmpty();
        assertThat(tagNode1.asString()).isEqualTo("TAG");

        // MessageDigest under Mac under PublicKeyEncryption
        INode messageDigestNode2 = macNode1.getChildren().get(MessageDigest.class);
        assertThat(messageDigestNode2).isNotNull();
        assertThat(messageDigestNode2.getChildren()).hasSize(4);
        assertThat(messageDigestNode2.asString()).isEqualTo("SHA512");

        // Oid under MessageDigest under Mac under PublicKeyEncryption
        INode oidNode3 = messageDigestNode2.getChildren().get(Oid.class);
        assertThat(oidNode3).isNotNull();
        assertThat(oidNode3.getChildren()).isEmpty();
        assertThat(oidNode3.asString()).isEqualTo("2.16.840.1.101.3.4.2.3");

        // DigestSize under MessageDigest under Mac under PublicKeyEncryption
        INode digestSizeNode2 = messageDigestNode2.getChildren().get(DigestSize.class);
        assertThat(digestSizeNode2).isNotNull();
        assertThat(digestSizeNode2.getChildren()).isEmpty();
        assertThat(digestSizeNode2.asString()).isEqualTo("512");

        // BlockSize under MessageDigest under Mac under PublicKeyEncryption
        INode blockSizeNode2 = messageDigestNode2.getChildren().get(BlockSize.class);
        assertThat(blockSizeNode2).isNotNull();
        assertThat(blockSizeNode2.getChildren()).isEmpty();
        assertThat(blockSizeNode2.asString()).isEqualTo("1024");

        // Digest under MessageDigest under Mac under PublicKeyEncryption
        INode digestNode2 = messageDigestNode2.getChildren().get(Digest.class);
        assertThat(digestNode2).isNotNull();
        assertThat(digestNode2.getChildren()).isEmpty();
        assertThat(digestNode2.asString()).isEqualTo("DIGEST");

        // TagLength under Mac under PublicKeyEncryption
        INode tagLengthNode = macNode1.getChildren().get(TagLength.class);
        assertThat(tagLengthNode).isNotNull();
        assertThat(tagLengthNode.getChildren()).isEmpty();
        assertThat(tagLengthNode.asString()).isEqualTo("128");

        // KeyDerivationFunction under PublicKeyEncryption
        INode keyDerivationFunctionNode1 =
                publicKeyEncryptionNode.getChildren().get(KeyDerivationFunction.class);
        assertThat(keyDerivationFunctionNode1).isNotNull();
        assertThat(keyDerivationFunctionNode1.getChildren()).hasSize(1);
        assertThat(keyDerivationFunctionNode1.asString()).isEqualTo("KDF1");

        // MessageDigest under KeyDerivationFunction under PublicKeyEncryption
        INode messageDigestNode3 =
                keyDerivationFunctionNode1.getChildren().get(MessageDigest.class);
        assertThat(messageDigestNode3).isNotNull();
        assertThat(messageDigestNode3.getChildren()).hasSize(4);
        assertThat(messageDigestNode3.asString()).isEqualTo("SHA256");

        // Oid under MessageDigest under KeyDerivationFunction under PublicKeyEncryption
        INode oidNode4 = messageDigestNode3.getChildren().get(Oid.class);
        assertThat(oidNode4).isNotNull();
        assertThat(oidNode4.getChildren()).isEmpty();
        assertThat(oidNode4.asString()).isEqualTo("2.16.840.1.101.3.4.2.1");

        // DigestSize under MessageDigest under KeyDerivationFunction under PublicKeyEncryption
        INode digestSizeNode3 = messageDigestNode3.getChildren().get(DigestSize.class);
        assertThat(digestSizeNode3).isNotNull();
        assertThat(digestSizeNode3.getChildren()).isEmpty();
        assertThat(digestSizeNode3.asString()).isEqualTo("256");

        // BlockSize under MessageDigest under KeyDerivationFunction under PublicKeyEncryption
        INode blockSizeNode3 = messageDigestNode3.getChildren().get(BlockSize.class);
        assertThat(blockSizeNode3).isNotNull();
        assertThat(blockSizeNode3.getChildren()).isEmpty();
        assertThat(blockSizeNode3.asString()).isEqualTo("512");

        // Digest under MessageDigest under KeyDerivationFunction under PublicKeyEncryption
        INode digestNode3 = messageDigestNode3.getChildren().get(Digest.class);
        assertThat(digestNode3).isNotNull();
        assertThat(digestNode3.getChildren()).isEmpty();
        assertThat(digestNode3.asString()).isEqualTo("DIGEST");

        // KeyAgreement under PublicKeyEncryption
        INode keyAgreementNode1 = publicKeyEncryptionNode.getChildren().get(KeyAgreement.class);
        assertThat(keyAgreementNode1).isNotNull();
        assertThat(keyAgreementNode1.getChildren()).hasSize(1);
        assertThat(keyAgreementNode1.asString()).isEqualTo("ECDH");

        // Oid under KeyAgreement under PublicKeyEncryption
        INode oidNode5 = keyAgreementNode1.getChildren().get(Oid.class);
        assertThat(oidNode5).isNotNull();
        assertThat(oidNode5.getChildren()).isEmpty();
        assertThat(oidNode5.asString()).isEqualTo("1.3.132.1.12");
    }
}
