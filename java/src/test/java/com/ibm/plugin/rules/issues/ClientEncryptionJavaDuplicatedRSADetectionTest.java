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
import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.CipherAction;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.OperationMode;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.functionality.Decapsulate;
import com.ibm.mapper.model.functionality.Encapsulate;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

class ClientEncryptionJavaDuplicatedRSADetectionTest extends TestBase {

    @Test
    @Disabled
    void test() {
        CheckVerifier.newVerifier()
                .onFile(
                        "src/test/files/rules/issues/ClientEncryptionJavaDuplicatedRSADetectionTestFile.java")
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
            assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(Algorithm.class);
            assertThat(value0.asString()).isEqualTo("RSA/ECB/OAEPWith{ALG}AndMGF1Padding");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_1 =
                    getStoreOfValueType(OperationMode.class, detectionStore.getChildren());
            assertThat(store_1.getDetectionValues()).hasSize(1);
            assertThat(store_1.getDetectionValueContext()).isInstanceOf(CipherContext.class);
            IValue<Tree> value0_1 = store_1.getDetectionValues().get(0);
            assertThat(value0_1).isInstanceOf(OperationMode.class);
            assertThat(value0_1.asString()).isEqualTo("3");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_2 =
                    getStoreOfValueType(CipherAction.class, detectionStore.getChildren());
            assertThat(store_2.getDetectionValues()).hasSize(1);
            assertThat(store_2.getDetectionValueContext()).isInstanceOf(CipherContext.class);
            IValue<Tree> value0_2 = store_2.getDetectionValues().get(0);
            assertThat(value0_2).isInstanceOf(CipherAction.class);
            assertThat(value0_2.asString()).isEqualTo("WRAP");

            /*
             * Translation
             */

            assertThat(nodes).hasSize(1);

            // PublicKeyEncryption
            INode publicKeyEncryptionNode = nodes.get(0);
            assertThat(publicKeyEncryptionNode.getKind()).isEqualTo(PublicKeyEncryption.class);
            assertThat(publicKeyEncryptionNode.getChildren()).hasSize(5);
            assertThat(publicKeyEncryptionNode.asString()).isEqualTo("RSA-OAEP");

            // KeyLength under PublicKeyEncryption
            INode keyLengthNode = publicKeyEncryptionNode.getChildren().get(KeyLength.class);
            assertThat(keyLengthNode).isNotNull();
            assertThat(keyLengthNode.getChildren()).isEmpty();
            assertThat(keyLengthNode.asString()).isEqualTo("2048");

            // Oid under PublicKeyEncryption
            INode oidNode = publicKeyEncryptionNode.getChildren().get(Oid.class);
            assertThat(oidNode).isNotNull();
            assertThat(oidNode.getChildren()).isEmpty();
            assertThat(oidNode.asString()).isEqualTo("1.2.840.113549.1.1.7");

            // Padding under PublicKeyEncryption
            INode paddingNode = publicKeyEncryptionNode.getChildren().get(Padding.class);
            assertThat(paddingNode).isNotNull();
            assertThat(paddingNode.getChildren()).isEmpty();
            assertThat(paddingNode.asString()).isEqualTo("OAEP");

            // Encapsulate under PublicKeyEncryption
            INode encapsulateNode = publicKeyEncryptionNode.getChildren().get(Encapsulate.class);
            assertThat(encapsulateNode).isNotNull();
            assertThat(encapsulateNode.getChildren()).isEmpty();
            assertThat(encapsulateNode.asString()).isEqualTo("ENCAPSULATE");

            // Mode under PublicKeyEncryption
            INode modeNode = publicKeyEncryptionNode.getChildren().get(Mode.class);
            assertThat(modeNode).isNotNull();
            assertThat(modeNode.getChildren()).isEmpty();
            assertThat(modeNode.asString()).isEqualTo("ECB");

        } else {
            /*
             * Detection Store
             */

            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(Algorithm.class);
            assertThat(value0.asString()).isEqualTo("RSA/ECB/OAEPWith{ALG}AndMGF1Padding");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_1 =
                    getStoreOfValueType(OperationMode.class, detectionStore.getChildren());
            assertThat(store_1.getDetectionValues()).hasSize(1);
            assertThat(store_1.getDetectionValueContext()).isInstanceOf(CipherContext.class);
            IValue<Tree> value0_1 = store_1.getDetectionValues().get(0);
            assertThat(value0_1).isInstanceOf(OperationMode.class);
            assertThat(value0_1.asString()).isEqualTo("4");

            /*
             * Translation
             */
            assertThat(nodes).hasSize(1);

            // PublicKeyEncryption
            INode publicKeyEncryptionNode1 = nodes.get(0);
            assertThat(publicKeyEncryptionNode1.getKind()).isEqualTo(PublicKeyEncryption.class);
            assertThat(publicKeyEncryptionNode1.getChildren()).hasSize(5);
            assertThat(publicKeyEncryptionNode1.asString()).isEqualTo("RSA-OAEP");

            // Mode under PublicKeyEncryption
            INode modeNode1 = publicKeyEncryptionNode1.getChildren().get(Mode.class);
            assertThat(modeNode1).isNotNull();
            assertThat(modeNode1.getChildren()).isEmpty();
            assertThat(modeNode1.asString()).isEqualTo("ECB");

            // Decapsulate under PublicKeyEncryption
            INode decapsulateNode = publicKeyEncryptionNode1.getChildren().get(Decapsulate.class);
            assertThat(decapsulateNode).isNotNull();
            assertThat(decapsulateNode.getChildren()).isEmpty();
            assertThat(decapsulateNode.asString()).isEqualTo("DECAPSULATE");

            // Oid under PublicKeyEncryption
            INode oidNode1 = publicKeyEncryptionNode1.getChildren().get(Oid.class);
            assertThat(oidNode1).isNotNull();
            assertThat(oidNode1.getChildren()).isEmpty();
            assertThat(oidNode1.asString()).isEqualTo("1.2.840.113549.1.1.7");

            // Padding under PublicKeyEncryption
            INode paddingNode1 = publicKeyEncryptionNode1.getChildren().get(Padding.class);
            assertThat(paddingNode1).isNotNull();
            assertThat(paddingNode1.getChildren()).isEmpty();
            assertThat(paddingNode1.asString()).isEqualTo("OAEP");

            // KeyLength under PublicKeyEncryption
            INode keyLengthNode1 = publicKeyEncryptionNode1.getChildren().get(KeyLength.class);
            assertThat(keyLengthNode1).isNotNull();
            assertThat(keyLengthNode1.getChildren()).isEmpty();
            assertThat(keyLengthNode1.asString()).isEqualTo("2048");
        }
    }
}
