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
package com.ibm.plugin.rules.issues;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.OperationMode;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.SecretKeyContext;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.SecretKey;
import com.ibm.mapper.model.functionality.Decrypt;
import com.ibm.mapper.model.functionality.Encrypt;
import com.ibm.mapper.model.functionality.KeyGeneration;
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

// https://github.com/IBM/sonar-cryptography/issues/224
class Issue224Test extends TestBase {

    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile("src/test/files/rules/issues/Issue224TestFile.java")
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
            assertThat(value0.asString()).isEqualTo("DES");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_1 =
                    getStoreOfValueType(KeyAction.class, detectionStore.getChildren());
            assertThat(store_1.getDetectionValues()).hasSize(1);
            assertThat(store_1.getDetectionValueContext()).isInstanceOf(SecretKeyContext.class);
            IValue<Tree> value0_1 = store_1.getDetectionValues().get(0);
            assertThat(value0_1).isInstanceOf(KeyAction.class);
            assertThat(value0_1.asString()).isEqualTo("GENERATION");

            /*
             * Translation
             */

            assertThat(nodes).hasSize(1);

            // SecretKey
            INode secretKeyNode = nodes.get(0);
            assertThat(secretKeyNode.getKind()).isEqualTo(SecretKey.class);
            assertThat(secretKeyNode.getChildren()).hasSize(1);
            assertThat(secretKeyNode.asString()).isEqualTo("DES");

            // BlockCipher under SecretKey
            INode blockCipherNode = secretKeyNode.getChildren().get(BlockCipher.class);
            assertThat(blockCipherNode).isNotNull();
            assertThat(blockCipherNode.getChildren()).hasSize(3);
            assertThat(blockCipherNode.asString()).isEqualTo("DES56");

            // KeyLength under BlockCipher under SecretKey
            INode keyLengthNode = blockCipherNode.getChildren().get(KeyLength.class);
            assertThat(keyLengthNode).isNotNull();
            assertThat(keyLengthNode.getChildren()).isEmpty();
            assertThat(keyLengthNode.asString()).isEqualTo("56");

            // BlockSize under BlockCipher under SecretKey
            INode blockSizeNode = blockCipherNode.getChildren().get(BlockSize.class);
            assertThat(blockSizeNode).isNotNull();
            assertThat(blockSizeNode.getChildren()).isEmpty();
            assertThat(blockSizeNode.asString()).isEqualTo("64");

            // KeyGeneration under BlockCipher under SecretKey
            INode keyGenerationNode = blockCipherNode.getChildren().get(KeyGeneration.class);
            assertThat(keyGenerationNode).isNotNull();
            assertThat(keyGenerationNode.getChildren()).isEmpty();
            assertThat(keyGenerationNode.asString()).isEqualTo("KEYGENERATION");
        } else if (findingId == 1) {
            /*
             * Detection Store
             */

            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(Algorithm.class);
            assertThat(value0.asString()).isEqualTo("DES");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_1 =
                    getStoreOfValueType(OperationMode.class, detectionStore.getChildren());
            assertThat(store_1.getDetectionValues()).hasSize(1);
            assertThat(store_1.getDetectionValueContext()).isInstanceOf(CipherContext.class);
            IValue<Tree> value0_1 = store_1.getDetectionValues().get(0);
            assertThat(value0_1).isInstanceOf(OperationMode.class);
            assertThat(value0_1.asString()).isEqualTo("1");

            /*
             * Translation
             */

            assertThat(nodes).hasSize(1);

            // BlockCipher
            INode blockCipherNode = nodes.get(0);
            assertThat(blockCipherNode.getKind()).isEqualTo(BlockCipher.class);
            assertThat(blockCipherNode.getChildren()).hasSize(3);
            assertThat(blockCipherNode.asString()).isEqualTo("DES56");

            // KeyLength under BlockCipher
            INode keyLengthNode = blockCipherNode.getChildren().get(KeyLength.class);
            assertThat(keyLengthNode).isNotNull();
            assertThat(keyLengthNode.getChildren()).isEmpty();
            assertThat(keyLengthNode.asString()).isEqualTo("56");

            // Encrypt under BlockCipher
            INode encryptNode = blockCipherNode.getChildren().get(Encrypt.class);
            assertThat(encryptNode).isNotNull();
            assertThat(encryptNode.getChildren()).isEmpty();
            assertThat(encryptNode.asString()).isEqualTo("ENCRYPT");

            // BlockSize under BlockCipher
            INode blockSizeNode = blockCipherNode.getChildren().get(BlockSize.class);
            assertThat(blockSizeNode).isNotNull();
            assertThat(blockSizeNode.getChildren()).isEmpty();
            assertThat(blockSizeNode.asString()).isEqualTo("64");
        } else if (findingId == 2) {
            /*
             * Detection Store
             */

            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext())
                    .isInstanceOf(SecretKeyContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(Algorithm.class);
            assertThat(value0.asString()).isEqualTo("DES");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_1 =
                    getStoreOfValueType(KeyAction.class, detectionStore.getChildren());
            assertThat(store_1.getDetectionValues()).hasSize(1);
            assertThat(store_1.getDetectionValueContext()).isInstanceOf(SecretKeyContext.class);
            IValue<Tree> value0_1 = store_1.getDetectionValues().get(0);
            assertThat(value0_1).isInstanceOf(KeyAction.class);
            assertThat(value0_1.asString()).isEqualTo("GENERATION");

            /*
             * Translation
             */

            assertThat(nodes).hasSize(1);

            // SecretKey
            INode secretKeyNode = nodes.get(0);
            assertThat(secretKeyNode.getKind()).isEqualTo(SecretKey.class);
            assertThat(secretKeyNode.getChildren()).hasSize(1);
            assertThat(secretKeyNode.asString()).isEqualTo("DES");

            // BlockCipher under SecretKey
            INode blockCipherNode = secretKeyNode.getChildren().get(BlockCipher.class);
            assertThat(blockCipherNode).isNotNull();
            assertThat(blockCipherNode.getChildren()).hasSize(3);
            assertThat(blockCipherNode.asString()).isEqualTo("DES56");

            // KeyLength under BlockCipher under SecretKey
            INode keyLengthNode = blockCipherNode.getChildren().get(KeyLength.class);
            assertThat(keyLengthNode).isNotNull();
            assertThat(keyLengthNode.getChildren()).isEmpty();
            assertThat(keyLengthNode.asString()).isEqualTo("56");

            // BlockSize under BlockCipher under SecretKey
            INode blockSizeNode = blockCipherNode.getChildren().get(BlockSize.class);
            assertThat(blockSizeNode).isNotNull();
            assertThat(blockSizeNode.getChildren()).isEmpty();
            assertThat(blockSizeNode.asString()).isEqualTo("64");

            // KeyGeneration under BlockCipher under SecretKey
            INode keyGenerationNode = blockCipherNode.getChildren().get(KeyGeneration.class);
            assertThat(keyGenerationNode).isNotNull();
            assertThat(keyGenerationNode.getChildren()).isEmpty();
            assertThat(keyGenerationNode.asString()).isEqualTo("KEYGENERATION");
        } else if (findingId == 3) {
            /*
             * Detection Store
             */

            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(Algorithm.class);
            assertThat(value0.asString()).isEqualTo("DES");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_1 =
                    getStoreOfValueType(OperationMode.class, detectionStore.getChildren());
            assertThat(store_1.getDetectionValues()).hasSize(1);
            assertThat(store_1.getDetectionValueContext()).isInstanceOf(CipherContext.class);
            IValue<Tree> value0_1 = store_1.getDetectionValues().get(0);
            assertThat(value0_1).isInstanceOf(OperationMode.class);
            assertThat(value0_1.asString()).isEqualTo("2");

            /*
             * Translation
             */

            assertThat(nodes).hasSize(1);

            // BlockCipher
            INode blockCipherNode = nodes.get(0);
            assertThat(blockCipherNode.getKind()).isEqualTo(BlockCipher.class);
            assertThat(blockCipherNode.getChildren()).hasSize(3);
            assertThat(blockCipherNode.asString()).isEqualTo("DES56");

            // KeyLength under BlockCipher
            INode keyLengthNode = blockCipherNode.getChildren().get(KeyLength.class);
            assertThat(keyLengthNode).isNotNull();
            assertThat(keyLengthNode.getChildren()).isEmpty();
            assertThat(keyLengthNode.asString()).isEqualTo("56");

            // Decrypt under BlockCipher
            INode decryptNode = blockCipherNode.getChildren().get(Decrypt.class);
            assertThat(decryptNode).isNotNull();
            assertThat(decryptNode.getChildren()).isEmpty();
            assertThat(decryptNode.asString()).isEqualTo("DECRYPT");

            // BlockSize under BlockCipher
            INode blockSizeNode = blockCipherNode.getChildren().get(BlockSize.class);
            assertThat(blockSizeNode).isNotNull();
            assertThat(blockSizeNode.getChildren()).isEmpty();
            assertThat(blockSizeNode.asString()).isEqualTo("64");
        } else if (findingId == 4) {
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

            // KeyLength under BlockCipher under SecretKey
            INode keyLengthNode = blockCipherNode.getChildren().get(KeyLength.class);
            assertThat(keyLengthNode).isNotNull();
            assertThat(keyLengthNode.getChildren()).isEmpty();
            assertThat(keyLengthNode.asString()).isEqualTo("128");

            // BlockSize under BlockCipher under SecretKey
            INode blockSizeNode = blockCipherNode.getChildren().get(BlockSize.class);
            assertThat(blockSizeNode).isNotNull();
            assertThat(blockSizeNode.getChildren()).isEmpty();
            assertThat(blockSizeNode.asString()).isEqualTo("128");

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
        } else if (findingId == 5) {
            /*
             * Detection Store
             */

            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(Algorithm.class);
            assertThat(value0.asString()).isEqualTo("AES/CBC/PKCS5Padding");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_1 =
                    getStoreOfValueType(OperationMode.class, detectionStore.getChildren());
            assertThat(store_1.getDetectionValues()).hasSize(1);
            assertThat(store_1.getDetectionValueContext()).isInstanceOf(CipherContext.class);
            IValue<Tree> value0_1 = store_1.getDetectionValues().get(0);
            assertThat(value0_1).isInstanceOf(OperationMode.class);
            assertThat(value0_1.asString()).isEqualTo("1");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_1_1 =
                    getStoreOfValueType(Algorithm.class, store_1.getChildren());
            assertThat(store_1_1.getDetectionValues()).hasSize(1);
            assertThat(store_1_1.getDetectionValueContext()).isInstanceOf(SecretKeyContext.class);
            IValue<Tree> value0_1_1 = store_1_1.getDetectionValues().get(0);
            assertThat(value0_1_1).isInstanceOf(Algorithm.class);
            assertThat(value0_1_1.asString()).isEqualTo("AES");

            /*
             * Translation
             */

            assertThat(nodes).hasSize(1);

            // BlockCipher
            INode blockCipherNode = nodes.get(0);
            assertThat(blockCipherNode.getKind()).isEqualTo(BlockCipher.class);
            assertThat(blockCipherNode.getChildren()).hasSize(7);
            assertThat(blockCipherNode.asString()).isEqualTo("AES128-CBC-PKCS5");

            // Oid under BlockCipher
            INode oidNode = blockCipherNode.getChildren().get(Oid.class);
            assertThat(oidNode).isNotNull();
            assertThat(oidNode.getChildren()).isEmpty();
            assertThat(oidNode.asString()).isEqualTo("2.16.840.1.101.3.4.1");

            // SecretKey under BlockCipher
            INode secretKeyNode = blockCipherNode.getChildren().get(SecretKey.class);
            assertThat(secretKeyNode).isNotNull();
            assertThat(secretKeyNode.getChildren()).hasSize(1);
            assertThat(secretKeyNode.asString()).isEqualTo("AES");

            // BlockCipher under SecretKey under BlockCipher
            INode blockCipherNode1 = secretKeyNode.getChildren().get(BlockCipher.class);
            assertThat(blockCipherNode1).isNotNull();
            assertThat(blockCipherNode1.getChildren()).hasSize(4);
            assertThat(blockCipherNode1.asString()).isEqualTo("AES128");

            // Oid under BlockCipher under SecretKey under BlockCipher
            INode oidNode1 = blockCipherNode1.getChildren().get(Oid.class);
            assertThat(oidNode1).isNotNull();
            assertThat(oidNode1.getChildren()).isEmpty();
            assertThat(oidNode1.asString()).isEqualTo("2.16.840.1.101.3.4.1");

            // KeyLength under BlockCipher under SecretKey under BlockCipher
            INode keyLengthNode = blockCipherNode1.getChildren().get(KeyLength.class);
            assertThat(keyLengthNode).isNotNull();
            assertThat(keyLengthNode.getChildren()).isEmpty();
            assertThat(keyLengthNode.asString()).isEqualTo("128");

            // BlockSize under BlockCipher under SecretKey under BlockCipher
            INode blockSizeNode = blockCipherNode1.getChildren().get(BlockSize.class);
            assertThat(blockSizeNode).isNotNull();
            assertThat(blockSizeNode.getChildren()).isEmpty();
            assertThat(blockSizeNode.asString()).isEqualTo("128");

            // KeyGeneration under BlockCipher under SecretKey under BlockCipher
            INode keyGenerationNode = blockCipherNode1.getChildren().get(KeyGeneration.class);
            assertThat(keyGenerationNode).isNotNull();
            assertThat(keyGenerationNode.getChildren()).isEmpty();
            assertThat(keyGenerationNode.asString()).isEqualTo("KEYGENERATION");

            // KeyLength under BlockCipher
            INode keyLengthNode1 = blockCipherNode.getChildren().get(KeyLength.class);
            assertThat(keyLengthNode1).isNotNull();
            assertThat(keyLengthNode1.getChildren()).isEmpty();
            assertThat(keyLengthNode1.asString()).isEqualTo("128");

            // Mode under BlockCipher
            INode modeNode = blockCipherNode.getChildren().get(Mode.class);
            assertThat(modeNode).isNotNull();
            assertThat(modeNode.getChildren()).isEmpty();
            assertThat(modeNode.asString()).isEqualTo("CBC");

            // BlockSize under BlockCipher
            INode blockSizeNode1 = blockCipherNode.getChildren().get(BlockSize.class);
            assertThat(blockSizeNode1).isNotNull();
            assertThat(blockSizeNode1.getChildren()).isEmpty();
            assertThat(blockSizeNode1.asString()).isEqualTo("128");

            // Encrypt under BlockCipher
            INode encryptNode = blockCipherNode.getChildren().get(Encrypt.class);
            assertThat(encryptNode).isNotNull();
            assertThat(encryptNode.getChildren()).isEmpty();
            assertThat(encryptNode.asString()).isEqualTo("ENCRYPT");

            // Padding under BlockCipher
            INode paddingNode = blockCipherNode.getChildren().get(Padding.class);
            assertThat(paddingNode).isNotNull();
            assertThat(paddingNode.getChildren()).isEmpty();
            assertThat(paddingNode.asString()).isEqualTo("PKCS5");
        } else if (findingId == 6) {
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

            // KeyLength under BlockCipher under SecretKey
            INode keyLengthNode = blockCipherNode.getChildren().get(KeyLength.class);
            assertThat(keyLengthNode).isNotNull();
            assertThat(keyLengthNode.getChildren()).isEmpty();
            assertThat(keyLengthNode.asString()).isEqualTo("128");

            // BlockSize under BlockCipher under SecretKey
            INode blockSizeNode = blockCipherNode.getChildren().get(BlockSize.class);
            assertThat(blockSizeNode).isNotNull();
            assertThat(blockSizeNode.getChildren()).isEmpty();
            assertThat(blockSizeNode.asString()).isEqualTo("128");
        } else if (findingId == 7) {
            /*
             * Detection Store
             */

            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(Algorithm.class);
            assertThat(value0.asString()).isEqualTo("AES/CBC/PKCS5Padding");

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

            /*
             * Translation
             */

            assertThat(nodes).hasSize(1);

            // BlockCipher
            INode blockCipherNode = nodes.get(0);
            assertThat(blockCipherNode.getKind()).isEqualTo(BlockCipher.class);
            assertThat(blockCipherNode.getChildren()).hasSize(7);
            assertThat(blockCipherNode.asString()).isEqualTo("AES128-CBC-PKCS5");

            // Padding under BlockCipher
            INode paddingNode = blockCipherNode.getChildren().get(Padding.class);
            assertThat(paddingNode).isNotNull();
            assertThat(paddingNode.getChildren()).isEmpty();
            assertThat(paddingNode.asString()).isEqualTo("PKCS5");

            // SecretKey under BlockCipher
            INode secretKeyNode = blockCipherNode.getChildren().get(SecretKey.class);
            assertThat(secretKeyNode).isNotNull();
            assertThat(secretKeyNode.getChildren()).hasSize(1);
            assertThat(secretKeyNode.asString()).isEqualTo("AES");

            // BlockCipher under SecretKey under BlockCipher
            INode blockCipherNode1 = secretKeyNode.getChildren().get(BlockCipher.class);
            assertThat(blockCipherNode1).isNotNull();
            assertThat(blockCipherNode1.getChildren()).hasSize(4);
            assertThat(blockCipherNode1.asString()).isEqualTo("AES128");

            // KeyGeneration under BlockCipher under SecretKey under BlockCipher
            INode keyGenerationNode = blockCipherNode1.getChildren().get(KeyGeneration.class);
            assertThat(keyGenerationNode).isNotNull();
            assertThat(keyGenerationNode.getChildren()).isEmpty();
            assertThat(keyGenerationNode.asString()).isEqualTo("KEYGENERATION");

            // BlockSize under BlockCipher under SecretKey under BlockCipher
            INode blockSizeNode = blockCipherNode1.getChildren().get(BlockSize.class);
            assertThat(blockSizeNode).isNotNull();
            assertThat(blockSizeNode.getChildren()).isEmpty();
            assertThat(blockSizeNode.asString()).isEqualTo("128");

            // KeyLength under BlockCipher under SecretKey under BlockCipher
            INode keyLengthNode = blockCipherNode1.getChildren().get(KeyLength.class);
            assertThat(keyLengthNode).isNotNull();
            assertThat(keyLengthNode.getChildren()).isEmpty();
            assertThat(keyLengthNode.asString()).isEqualTo("128");

            // Oid under BlockCipher under SecretKey under BlockCipher
            INode oidNode = blockCipherNode1.getChildren().get(Oid.class);
            assertThat(oidNode).isNotNull();
            assertThat(oidNode.getChildren()).isEmpty();
            assertThat(oidNode.asString()).isEqualTo("2.16.840.1.101.3.4.1");

            // Mode under BlockCipher
            INode modeNode = blockCipherNode.getChildren().get(Mode.class);
            assertThat(modeNode).isNotNull();
            assertThat(modeNode.getChildren()).isEmpty();
            assertThat(modeNode.asString()).isEqualTo("CBC");

            // Decrypt under BlockCipher
            INode decryptNode = blockCipherNode.getChildren().get(Decrypt.class);
            assertThat(decryptNode).isNotNull();
            assertThat(decryptNode.getChildren()).isEmpty();
            assertThat(decryptNode.asString()).isEqualTo("DECRYPT");

            // BlockSize under BlockCipher
            INode blockSizeNode1 = blockCipherNode.getChildren().get(BlockSize.class);
            assertThat(blockSizeNode1).isNotNull();
            assertThat(blockSizeNode1.getChildren()).isEmpty();
            assertThat(blockSizeNode1.asString()).isEqualTo("128");

            // KeyLength under BlockCipher
            INode keyLengthNode1 = blockCipherNode.getChildren().get(KeyLength.class);
            assertThat(keyLengthNode1).isNotNull();
            assertThat(keyLengthNode1.getChildren()).isEmpty();
            assertThat(keyLengthNode1.asString()).isEqualTo("128");

            // Oid under BlockCipher
            INode oidNode1 = blockCipherNode.getChildren().get(Oid.class);
            assertThat(oidNode1).isNotNull();
            assertThat(oidNode1.getChildren()).isEmpty();
            assertThat(oidNode1.asString()).isEqualTo("2.16.840.1.101.3.4.1");
        } else if (findingId == 8) {
            /*
             * Detection Store
             */

            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext())
                    .isInstanceOf(SecretKeyContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(Algorithm.class);
            assertThat(value0.asString()).isEqualTo("DESede");

            /*
             * Translation
             */

            assertThat(nodes).hasSize(1);

            // SecretKey
            INode secretKeyNode = nodes.get(0);
            assertThat(secretKeyNode.getKind()).isEqualTo(SecretKey.class);
            assertThat(secretKeyNode.getChildren()).hasSize(1);
            assertThat(secretKeyNode.asString()).isEqualTo("3DES");

            // BlockCipher under SecretKey
            INode blockCipherNode = secretKeyNode.getChildren().get(BlockCipher.class);
            assertThat(blockCipherNode).isNotNull();
            assertThat(blockCipherNode.getChildren()).hasSize(2);
            assertThat(blockCipherNode.asString()).isEqualTo("3DES");

            // KeyGeneration under BlockCipher under SecretKey
            INode keyGenerationNode = blockCipherNode.getChildren().get(KeyGeneration.class);
            assertThat(keyGenerationNode).isNotNull();
            assertThat(keyGenerationNode.getChildren()).isEmpty();
            assertThat(keyGenerationNode.asString()).isEqualTo("KEYGENERATION");

            // BlockSize under BlockCipher under SecretKey
            INode blockSizeNode = blockCipherNode.getChildren().get(BlockSize.class);
            assertThat(blockSizeNode).isNotNull();
            assertThat(blockSizeNode.getChildren()).isEmpty();
            assertThat(blockSizeNode.asString()).isEqualTo("64");
        } else if (findingId == 9) {
            /*
             * Detection Store
             */

            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(Algorithm.class);
            assertThat(value0.asString()).isEqualTo("DESede/CBC/PKCS5Padding");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_1 =
                    getStoreOfValueType(OperationMode.class, detectionStore.getChildren());
            assertThat(store_1.getDetectionValues()).hasSize(1);
            assertThat(store_1.getDetectionValueContext()).isInstanceOf(CipherContext.class);
            IValue<Tree> value0_1 = store_1.getDetectionValues().get(0);
            assertThat(value0_1).isInstanceOf(OperationMode.class);
            assertThat(value0_1.asString()).isEqualTo("1");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_1_1 =
                    getStoreOfValueType(Algorithm.class, store_1.getChildren());
            assertThat(store_1_1.getDetectionValues()).hasSize(1);
            assertThat(store_1_1.getDetectionValueContext()).isInstanceOf(SecretKeyContext.class);
            IValue<Tree> value0_1_1 = store_1_1.getDetectionValues().get(0);
            assertThat(value0_1_1).isInstanceOf(Algorithm.class);
            assertThat(value0_1_1.asString()).isEqualTo("DESede");

            /*
             * Translation
             */

            assertThat(nodes).hasSize(1);

            // BlockCipher
            INode blockCipherNode = nodes.get(0);
            assertThat(blockCipherNode.getKind()).isEqualTo(BlockCipher.class);
            assertThat(blockCipherNode.getChildren()).hasSize(5);
            assertThat(blockCipherNode.asString()).isEqualTo("3DES");

            // BlockSize under BlockCipher
            INode blockSizeNode = blockCipherNode.getChildren().get(BlockSize.class);
            assertThat(blockSizeNode).isNotNull();
            assertThat(blockSizeNode.getChildren()).isEmpty();
            assertThat(blockSizeNode.asString()).isEqualTo("64");

            // Mode under BlockCipher
            INode modeNode = blockCipherNode.getChildren().get(Mode.class);
            assertThat(modeNode).isNotNull();
            assertThat(modeNode.getChildren()).isEmpty();
            assertThat(modeNode.asString()).isEqualTo("CBC");

            // Encrypt under BlockCipher
            INode encryptNode = blockCipherNode.getChildren().get(Encrypt.class);
            assertThat(encryptNode).isNotNull();
            assertThat(encryptNode.getChildren()).isEmpty();
            assertThat(encryptNode.asString()).isEqualTo("ENCRYPT");

            // SecretKey under BlockCipher
            INode secretKeyNode = blockCipherNode.getChildren().get(SecretKey.class);
            assertThat(secretKeyNode).isNotNull();
            assertThat(secretKeyNode.getChildren()).hasSize(1);
            assertThat(secretKeyNode.asString()).isEqualTo("3DES");

            // BlockCipher under SecretKey under BlockCipher
            INode blockCipherNode1 = secretKeyNode.getChildren().get(BlockCipher.class);
            assertThat(blockCipherNode1).isNotNull();
            assertThat(blockCipherNode1.getChildren()).hasSize(2);
            assertThat(blockCipherNode1.asString()).isEqualTo("3DES");

            // BlockSize under BlockCipher under SecretKey under BlockCipher
            INode blockSizeNode1 = blockCipherNode1.getChildren().get(BlockSize.class);
            assertThat(blockSizeNode1).isNotNull();
            assertThat(blockSizeNode1.getChildren()).isEmpty();
            assertThat(blockSizeNode1.asString()).isEqualTo("64");

            // KeyGeneration under BlockCipher under SecretKey under BlockCipher
            INode keyGenerationNode = blockCipherNode1.getChildren().get(KeyGeneration.class);
            assertThat(keyGenerationNode).isNotNull();
            assertThat(keyGenerationNode.getChildren()).isEmpty();
            assertThat(keyGenerationNode.asString()).isEqualTo("KEYGENERATION");

            // Padding under BlockCipher
            INode paddingNode = blockCipherNode.getChildren().get(Padding.class);
            assertThat(paddingNode).isNotNull();
            assertThat(paddingNode.getChildren()).isEmpty();
            assertThat(paddingNode.asString()).isEqualTo("PKCS5");
        } else if (findingId == 10) {
            /*
             * Detection Store
             */

            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext())
                    .isInstanceOf(SecretKeyContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(Algorithm.class);
            assertThat(value0.asString()).isEqualTo("DESede");

            /*
             * Translation
             */

            assertThat(nodes).hasSize(1);

            // SecretKey
            INode secretKeyNode = nodes.get(0);
            assertThat(secretKeyNode.getKind()).isEqualTo(SecretKey.class);
            assertThat(secretKeyNode.getChildren()).hasSize(1);
            assertThat(secretKeyNode.asString()).isEqualTo("3DES");

            // BlockCipher under SecretKey
            INode blockCipherNode = secretKeyNode.getChildren().get(BlockCipher.class);
            assertThat(blockCipherNode).isNotNull();
            assertThat(blockCipherNode.getChildren()).hasSize(2);
            assertThat(blockCipherNode.asString()).isEqualTo("3DES");

            // BlockSize under BlockCipher under SecretKey
            INode blockSizeNode = blockCipherNode.getChildren().get(BlockSize.class);
            assertThat(blockSizeNode).isNotNull();
            assertThat(blockSizeNode.getChildren()).isEmpty();
            assertThat(blockSizeNode.asString()).isEqualTo("64");

            // KeyGeneration under BlockCipher under SecretKey
            INode keyGenerationNode = blockCipherNode.getChildren().get(KeyGeneration.class);
            assertThat(keyGenerationNode).isNotNull();
            assertThat(keyGenerationNode.getChildren()).isEmpty();
            assertThat(keyGenerationNode.asString()).isEqualTo("KEYGENERATION");
        } else if (findingId == 11) {
            /*
             * Detection Store
             */

            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(Algorithm.class);
            assertThat(value0.asString()).isEqualTo("DESede/CBC/PKCS5Padding");

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
            assertThat(value0_1_1.asString()).isEqualTo("DESede");

            /*
             * Translation
             */

            assertThat(nodes).hasSize(1);

            // BlockCipher
            INode blockCipherNode = nodes.get(0);
            assertThat(blockCipherNode.getKind()).isEqualTo(BlockCipher.class);
            assertThat(blockCipherNode.getChildren()).hasSize(5);
            assertThat(blockCipherNode.asString()).isEqualTo("3DES");

            // BlockSize under BlockCipher
            INode blockSizeNode = blockCipherNode.getChildren().get(BlockSize.class);
            assertThat(blockSizeNode).isNotNull();
            assertThat(blockSizeNode.getChildren()).isEmpty();
            assertThat(blockSizeNode.asString()).isEqualTo("64");

            // Mode under BlockCipher
            INode modeNode = blockCipherNode.getChildren().get(Mode.class);
            assertThat(modeNode).isNotNull();
            assertThat(modeNode.getChildren()).isEmpty();
            assertThat(modeNode.asString()).isEqualTo("CBC");

            // Decrypt under BlockCipher
            INode decryptNode = blockCipherNode.getChildren().get(Decrypt.class);
            assertThat(decryptNode).isNotNull();
            assertThat(decryptNode.getChildren()).isEmpty();
            assertThat(decryptNode.asString()).isEqualTo("DECRYPT");

            // SecretKey under BlockCipher
            INode secretKeyNode = blockCipherNode.getChildren().get(SecretKey.class);
            assertThat(secretKeyNode).isNotNull();
            assertThat(secretKeyNode.getChildren()).hasSize(1);
            assertThat(secretKeyNode.asString()).isEqualTo("3DES");

            // BlockCipher under SecretKey under BlockCipher
            INode blockCipherNode1 = secretKeyNode.getChildren().get(BlockCipher.class);
            assertThat(blockCipherNode1).isNotNull();
            assertThat(blockCipherNode1.getChildren()).hasSize(2);
            assertThat(blockCipherNode1.asString()).isEqualTo("3DES");

            // BlockSize under BlockCipher under SecretKey under BlockCipher
            INode blockSizeNode1 = blockCipherNode1.getChildren().get(BlockSize.class);
            assertThat(blockSizeNode1).isNotNull();
            assertThat(blockSizeNode1.getChildren()).isEmpty();
            assertThat(blockSizeNode1.asString()).isEqualTo("64");

            // KeyGeneration under BlockCipher under SecretKey under BlockCipher
            INode keyGenerationNode = blockCipherNode1.getChildren().get(KeyGeneration.class);
            assertThat(keyGenerationNode).isNotNull();
            assertThat(keyGenerationNode.getChildren()).isEmpty();
            assertThat(keyGenerationNode.asString()).isEqualTo("KEYGENERATION");

            // Padding under BlockCipher
            INode paddingNode = blockCipherNode.getChildren().get(Padding.class);
            assertThat(paddingNode).isNotNull();
            assertThat(paddingNode.getChildren()).isEmpty();
            assertThat(paddingNode.asString()).isEqualTo("PKCS5");
        }
    }
}
