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
import com.ibm.mapper.model.AuthenticatedEncryption;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.Oid;
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

class Issue16Test extends TestBase {

    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile("src/test/files/rules/issues/Issue16TestFile.java")
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
            /*
             * Detection Store
             */
            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(ValueAction.class);
            assertThat(value0.asString()).isEqualTo("GCMBlockCipher");

            DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_1 =
                    getStoreOfValueType(ValueAction.class, detectionStore.getChildren());
            assertThat(store_1.getDetectionValues()).hasSize(1);
            assertThat(store_1.getDetectionValueContext()).isInstanceOf(CipherContext.class);
            IValue<Tree> value0_1 = store_1.getDetectionValues().get(0);
            assertThat(value0_1).isInstanceOf(ValueAction.class);
            assertThat(value0_1.asString()).isEqualTo("AESEngine");

            /*
             * Translation
             */
            assertThat(nodes).hasSize(1);

            // AuthenticatedEncryption
            INode authenticatedEncryptionNode = nodes.get(0);
            assertThat(authenticatedEncryptionNode.getKind())
                    .isEqualTo(AuthenticatedEncryption.class);
            assertThat(authenticatedEncryptionNode.getChildren()).hasSize(3);
            assertThat(authenticatedEncryptionNode.asString()).isEqualTo("AES-GCM");

            // BlockSize under AuthenticatedEncryption
            INode blockSizeNode = authenticatedEncryptionNode.getChildren().get(BlockSize.class);
            assertThat(blockSizeNode).isNotNull();
            assertThat(blockSizeNode.getChildren()).isEmpty();
            assertThat(blockSizeNode.asString()).isEqualTo("128");

            // Oid under AuthenticatedEncryption
            INode oidNode = authenticatedEncryptionNode.getChildren().get(Oid.class);
            assertThat(oidNode).isNotNull();
            assertThat(oidNode.getChildren()).isEmpty();
            assertThat(oidNode.asString()).isEqualTo("2.16.840.1.101.3.4.1");

            // Mode under AuthenticatedEncryption
            INode modeNode = authenticatedEncryptionNode.getChildren().get(Mode.class);
            assertThat(modeNode).isNotNull();
            assertThat(modeNode.getChildren()).isEmpty();
            assertThat(modeNode.asString()).isEqualTo("GCM");

        } else if (findingId == 1) {
            /*
             * Detection Store
             */
            assertThat(detectionStore.getDetectionValues()).hasSize(1);
            assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
            IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
            assertThat(value0).isInstanceOf(ValueAction.class);
            assertThat(value0.asString()).isEqualTo("AESEngine");

            /*
             * Translation
             */
            assertThat(nodes).hasSize(1);

            // BlockCipher
            INode blockCipherNode = nodes.get(0);
            assertThat(blockCipherNode.getKind()).isEqualTo(BlockCipher.class);
            assertThat(blockCipherNode.getChildren()).hasSize(2);
            assertThat(blockCipherNode.asString()).isEqualTo("AES");

            // BlockSize under BlockCipher
            INode blockSizeNode1 = blockCipherNode.getChildren().get(BlockSize.class);
            assertThat(blockSizeNode1).isNotNull();
            assertThat(blockSizeNode1.getChildren()).isEmpty();
            assertThat(blockSizeNode1.asString()).isEqualTo("128");

            // Oid under BlockCipher
            INode oidNode1 = blockCipherNode.getChildren().get(Oid.class);
            assertThat(oidNode1).isNotNull();
            assertThat(oidNode1.getChildren()).isEmpty();
            assertThat(oidNode1.asString()).isEqualTo("2.16.840.1.101.3.4.1");
        }
    }
}
