/*
 * SonarQube Cryptography Plugin
 * Copyright (C) 2025 IBM
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
package com.ibm.plugin.rules.detection.jca.algorithmspec;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.OperationMode;
import com.ibm.engine.model.PasswordSize;
import com.ibm.engine.model.SaltSize;
import com.ibm.engine.model.TagSize;
import com.ibm.engine.model.context.AlgorithmParameterContext;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.SecretKeyContext;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.PasswordBasedKeyDerivationFunction;
import com.ibm.mapper.model.PasswordLength;
import com.ibm.mapper.model.SaltLength;
import com.ibm.mapper.model.SecretKey;
import com.ibm.mapper.model.TagLength;
import com.ibm.mapper.model.functionality.Decrypt;
import com.ibm.mapper.model.functionality.Digest;
import com.ibm.mapper.model.functionality.KeyGeneration;
import com.ibm.mapper.model.functionality.Tag;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

class JcaGCMParameterSpecTest extends TestBase {

    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile(
                        "src/test/files/rules/detection/jca/algorithmspec/JcaGCMParameterSpecTestFile.java")
                .withChecks(this)
                .verifyIssues();
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes) {
        if (findingId == 0) {
            /*
             * Detection Store
             */

            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext())
                    .isInstanceOf(SecretKeyContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(Algorithm.class);
            assertThat(value0.asString()).isEqualTo("PBKDF2WithHmacSHA256");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_1 =
                    getStoreOfValueType(KeyAction.class, detectionStore.getChildren());
            assertThat(store_1.getDetectionValues()).hasSize(1);
            assertThat(store_1.getDetectionValueContext()).isInstanceOf(SecretKeyContext.class);
            IValue<Tree> value0_1 = store_1.getDetectionValues().get(0);
            assertThat(value0_1).isInstanceOf(KeyAction.class);
            assertThat(value0_1.asString()).isEqualTo("GENERATION");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_1_1 =
                    getStoreOfValueType(PasswordSize.class, store_1.getChildren());
            assertThat(store_1_1.getDetectionValues()).hasSize(3);
            assertThat(store_1_1.getDetectionValueContext()).isInstanceOf(SecretKeyContext.class);
            IValue<Tree> value0_1_1 = store_1_1.getDetectionValues().get(0);
            assertThat(value0_1_1).isInstanceOf(PasswordSize.class);
            assertThat(value0_1_1.asString()).isEqualTo("64");

            IValue<Tree> value1_1_1 = store_1_1.getDetectionValues().get(1);
            assertThat(value1_1_1).isInstanceOf(SaltSize.class);
            assertThat(value1_1_1.asString()).isEqualTo("32");

            IValue<Tree> value2_1_1 = store_1_1.getDetectionValues().get(2);
            assertThat(value2_1_1).isInstanceOf(KeySize.class);
            assertThat(value2_1_1.asString()).isEqualTo("256");

            /*
             * Translation
             */

            assertThat(nodes).hasSize(1);

            // SecretKey
            INode secretKeyNode = nodes.get(0);
            assertThat(secretKeyNode.getKind()).isEqualTo(SecretKey.class);
            assertThat(secretKeyNode.getChildren()).hasSize(4);
            assertThat(secretKeyNode.asString()).isEqualTo("PBKDF2");

            // KeyLength under SecretKey
            INode keyLengthNode = secretKeyNode.getChildren().get(KeyLength.class);
            assertThat(keyLengthNode).isNotNull();
            assertThat(keyLengthNode.getChildren()).isEmpty();
            assertThat(keyLengthNode.asString()).isEqualTo("256");

            // SaltLength under SecretKey
            INode saltLengthNode = secretKeyNode.getChildren().get(SaltLength.class);
            assertThat(saltLengthNode).isNotNull();
            assertThat(saltLengthNode.getChildren()).isEmpty();
            assertThat(saltLengthNode.asString()).isEqualTo("32");

            // PasswordBasedKeyDerivationFunction under SecretKey
            INode passwordBasedKeyDerivationFunctionNode =
                    secretKeyNode.getChildren().get(PasswordBasedKeyDerivationFunction.class);
            assertThat(passwordBasedKeyDerivationFunctionNode).isNotNull();
            assertThat(passwordBasedKeyDerivationFunctionNode.getChildren()).hasSize(2);
            assertThat(passwordBasedKeyDerivationFunctionNode.asString())
                    .isEqualTo("PBKDF2-HMAC-SHA256");

            // Mac under PasswordBasedKeyDerivationFunction under SecretKey
            INode macNode = passwordBasedKeyDerivationFunctionNode.getChildren().get(Mac.class);
            assertThat(macNode).isNotNull();
            assertThat(macNode.getChildren()).hasSize(3);
            assertThat(macNode.asString()).isEqualTo("HMAC-SHA256");

            // Oid under Mac under PasswordBasedKeyDerivationFunction under SecretKey
            INode oidNode = macNode.getChildren().get(Oid.class);
            assertThat(oidNode).isNotNull();
            assertThat(oidNode.getChildren()).isEmpty();
            assertThat(oidNode.asString()).isEqualTo("1.2.840.113549.2.9");

            // MessageDigest under Mac under PasswordBasedKeyDerivationFunction under SecretKey
            INode messageDigestNode = macNode.getChildren().get(MessageDigest.class);
            assertThat(messageDigestNode).isNotNull();
            assertThat(messageDigestNode.getChildren()).hasSize(4);
            assertThat(messageDigestNode.asString()).isEqualTo("SHA256");

            // Oid under MessageDigest under Mac under PasswordBasedKeyDerivationFunction under
            // SecretKey
            INode oidNode1 = messageDigestNode.getChildren().get(Oid.class);
            assertThat(oidNode1).isNotNull();
            assertThat(oidNode1.getChildren()).isEmpty();
            assertThat(oidNode1.asString()).isEqualTo("2.16.840.1.101.3.4.2.1");

            // BlockSize under MessageDigest under Mac under PasswordBasedKeyDerivationFunction
            // under SecretKey
            INode blockSizeNode = messageDigestNode.getChildren().get(BlockSize.class);
            assertThat(blockSizeNode).isNotNull();
            assertThat(blockSizeNode.getChildren()).isEmpty();
            assertThat(blockSizeNode.asString()).isEqualTo("512");

            // DigestSize under MessageDigest under Mac under PasswordBasedKeyDerivationFunction
            // under SecretKey
            INode digestSizeNode = messageDigestNode.getChildren().get(DigestSize.class);
            assertThat(digestSizeNode).isNotNull();
            assertThat(digestSizeNode.getChildren()).isEmpty();
            assertThat(digestSizeNode.asString()).isEqualTo("256");

            // Digest under MessageDigest under Mac under PasswordBasedKeyDerivationFunction under
            // SecretKey
            INode digestNode = messageDigestNode.getChildren().get(Digest.class);
            assertThat(digestNode).isNotNull();
            assertThat(digestNode.getChildren()).isEmpty();
            assertThat(digestNode.asString()).isEqualTo("DIGEST");

            // Tag under Mac under PasswordBasedKeyDerivationFunction under SecretKey
            INode tagNode = macNode.getChildren().get(Tag.class);
            assertThat(tagNode).isNotNull();
            assertThat(tagNode.getChildren()).isEmpty();
            assertThat(tagNode.asString()).isEqualTo("TAG");

            // KeyGeneration under PasswordBasedKeyDerivationFunction under SecretKey
            INode keyGenerationNode =
                    passwordBasedKeyDerivationFunctionNode.getChildren().get(KeyGeneration.class);
            assertThat(keyGenerationNode).isNotNull();
            assertThat(keyGenerationNode.getChildren()).isEmpty();
            assertThat(keyGenerationNode.asString()).isEqualTo("KEYGENERATION");

            // PasswordLength under SecretKey
            INode passwordLengthNode = secretKeyNode.getChildren().get(PasswordLength.class);
            assertThat(passwordLengthNode).isNotNull();
            assertThat(passwordLengthNode.getChildren()).isEmpty();
            assertThat(passwordLengthNode.asString()).isEqualTo("64");

        } else if (findingId == 1) {
            /*
             * Detection Store
             */

            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext())
                    .isInstanceOf(SecretKeyContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(Algorithm.class);
            assertThat(value0.asString()).isEqualTo("AES");

            /*
             * Translation
             */

            assertThat(nodes).hasSize(1);

            // SecretKey
            INode secretKeyNode = nodes.get(0);
            assertThat(secretKeyNode.getKind()).isEqualTo(SecretKey.class);
            assertThat(secretKeyNode.getChildren()).hasSize(1);
            assertThat(secretKeyNode.asString()).isEqualTo("AES");

            // BlockCipher under SecretKey
            INode blockCipherNode = secretKeyNode.getChildren().get(BlockCipher.class);
            assertThat(blockCipherNode).isNotNull();
            assertThat(blockCipherNode.getChildren()).hasSize(4);
            assertThat(blockCipherNode.asString()).isEqualTo("AES128");

            // BlockSize under BlockCipher under SecretKey
            INode blockSizeNode = blockCipherNode.getChildren().get(BlockSize.class);
            assertThat(blockSizeNode).isNotNull();
            assertThat(blockSizeNode.getChildren()).isEmpty();
            assertThat(blockSizeNode.asString()).isEqualTo("128");

            // KeyLength under BlockCipher under SecretKey
            INode keyLengthNode = blockCipherNode.getChildren().get(KeyLength.class);
            assertThat(keyLengthNode).isNotNull();
            assertThat(keyLengthNode.getChildren()).isEmpty();
            assertThat(keyLengthNode.asString()).isEqualTo("128");

            // Oid under BlockCipher under SecretKey
            INode oidNode = blockCipherNode.getChildren().get(Oid.class);
            assertThat(oidNode).isNotNull();
            assertThat(oidNode.getChildren()).isEmpty();
            assertThat(oidNode.asString()).isEqualTo("2.16.840.1.101.3.4.1");

            // KeyGeneration under BlockCipher under SecretKey
            INode keyGenerationNode = blockCipherNode.getChildren().get(KeyGeneration.class);
            assertThat(keyGenerationNode).isNotNull();
            assertThat(keyGenerationNode.getChildren()).isEmpty();
            assertThat(keyGenerationNode.asString()).isEqualTo("KEYGENERATION");
        } else if (findingId == 2) {
            /*
             * Detection Store
             */

            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(Algorithm.class);
            assertThat(value0.asString()).isEqualTo("AES");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_1 =
                    getStoreOfValueType(OperationMode.class, detectionStore.getChildren());
            assertThat(store_1.getDetectionValues()).hasSize(1);
            assertThat(store_1.getDetectionValueContext()).isInstanceOf(CipherContext.class);
            IValue<Tree> value0_1 = store_1.getDetectionValues().get(0);
            assertThat(value0_1).isInstanceOf(OperationMode.class);
            assertThat(value0_1.asString()).isEqualTo("2");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_1_1 =
                    getStoreOfValueType(Algorithm.class, store_1.getChildren());
            assertThat(store_1_1.getDetectionValues()).hasSize(1);
            assertThat(store_1_1.getDetectionValueContext()).isInstanceOf(SecretKeyContext.class);
            IValue<Tree> value0_1_1 = store_1_1.getDetectionValues().get(0);
            assertThat(value0_1_1).isInstanceOf(Algorithm.class);
            assertThat(value0_1_1.asString()).isEqualTo("AES");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_1_2 =
                    getStoreOfValueType(TagSize.class, store_1.getChildren());
            assertThat(store_1_2.getDetectionValues()).hasSize(1);
            assertThat(store_1_2.getDetectionValueContext())
                    .isInstanceOf(AlgorithmParameterContext.class);
            IValue<Tree> value0_1_2 = store_1_2.getDetectionValues().get(0);
            assertThat(value0_1_2).isInstanceOf(TagSize.class);
            assertThat(value0_1_2.asString()).isEqualTo("128");

            /*
             * Translation
             */

            assertThat(nodes).hasSize(1);

            // BlockCipher
            INode blockCipherNode1 = nodes.get(0);
            assertThat(blockCipherNode1.getKind()).isEqualTo(BlockCipher.class);
            assertThat(blockCipherNode1.getChildren()).hasSize(6);
            assertThat(blockCipherNode1.asString()).isEqualTo("AES128");

            // TagLength under BlockCipher
            INode tagLengthNode = blockCipherNode1.getChildren().get(TagLength.class);
            assertThat(tagLengthNode).isNotNull();
            assertThat(tagLengthNode.getChildren()).isEmpty();
            assertThat(tagLengthNode.asString()).isEqualTo("128");

            // Oid under BlockCipher
            INode oidNode2 = blockCipherNode1.getChildren().get(Oid.class);
            assertThat(oidNode2).isNotNull();
            assertThat(oidNode2.getChildren()).isEmpty();
            assertThat(oidNode2.asString()).isEqualTo("2.16.840.1.101.3.4.1");

            // Decrypt under BlockCipher
            INode decryptNode = blockCipherNode1.getChildren().get(Decrypt.class);
            assertThat(decryptNode).isNotNull();
            assertThat(decryptNode.getChildren()).isEmpty();
            assertThat(decryptNode.asString()).isEqualTo("DECRYPT");

            // SecretKey under BlockCipher
            INode secretKeyNode2 = blockCipherNode1.getChildren().get(SecretKey.class);
            assertThat(secretKeyNode2).isNotNull();
            assertThat(secretKeyNode2.getChildren()).hasSize(1);
            assertThat(secretKeyNode2.asString()).isEqualTo("AES");

            // BlockCipher under SecretKey under BlockCipher
            INode blockCipherNode2 = secretKeyNode2.getChildren().get(BlockCipher.class);
            assertThat(blockCipherNode2).isNotNull();
            assertThat(blockCipherNode2.getChildren()).hasSize(4);
            assertThat(blockCipherNode2.asString()).isEqualTo("AES128");

            // Oid under BlockCipher under SecretKey under BlockCipher
            INode oidNode3 = blockCipherNode2.getChildren().get(Oid.class);
            assertThat(oidNode3).isNotNull();
            assertThat(oidNode3.getChildren()).isEmpty();
            assertThat(oidNode3.asString()).isEqualTo("2.16.840.1.101.3.4.1");

            // KeyGeneration under BlockCipher under SecretKey under BlockCipher
            INode keyGenerationNode2 = blockCipherNode2.getChildren().get(KeyGeneration.class);
            assertThat(keyGenerationNode2).isNotNull();
            assertThat(keyGenerationNode2.getChildren()).isEmpty();
            assertThat(keyGenerationNode2.asString()).isEqualTo("KEYGENERATION");

            // KeyLength under BlockCipher under SecretKey under BlockCipher
            INode keyLengthNode2 = blockCipherNode2.getChildren().get(KeyLength.class);
            assertThat(keyLengthNode2).isNotNull();
            assertThat(keyLengthNode2.getChildren()).isEmpty();
            assertThat(keyLengthNode2.asString()).isEqualTo("128");

            // BlockSize under BlockCipher under SecretKey under BlockCipher
            INode blockSizeNode2 = blockCipherNode2.getChildren().get(BlockSize.class);
            assertThat(blockSizeNode2).isNotNull();
            assertThat(blockSizeNode2.getChildren()).isEmpty();
            assertThat(blockSizeNode2.asString()).isEqualTo("128");

            // KeyLength under BlockCipher
            INode keyLengthNode3 = blockCipherNode1.getChildren().get(KeyLength.class);
            assertThat(keyLengthNode3).isNotNull();
            assertThat(keyLengthNode3.getChildren()).isEmpty();
            assertThat(keyLengthNode3.asString()).isEqualTo("128");

            // BlockSize under BlockCipher
            INode blockSizeNode3 = blockCipherNode1.getChildren().get(BlockSize.class);
            assertThat(blockSizeNode3).isNotNull();
            assertThat(blockSizeNode3.getChildren()).isEmpty();
            assertThat(blockSizeNode3.asString()).isEqualTo("128");
        }
    }
}
