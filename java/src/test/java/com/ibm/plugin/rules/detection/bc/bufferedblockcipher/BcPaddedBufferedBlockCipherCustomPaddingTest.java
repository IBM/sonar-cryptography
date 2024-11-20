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
package com.ibm.plugin.rules.detection.bc.bufferedblockcipher;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.OperationMode;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.functionality.Encrypt;
import com.ibm.plugin.TestBase;
import com.ibm.plugin.rules.detection.bc.BouncyCastleJars;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

class BcPaddedBufferedBlockCipherCustomPaddingTest extends TestBase {
    @Disabled(
            "There is an undesirable AES detection at the same level than CBC: it should not be the case")
    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile(
                        "src/test/files/rules/detection/bc/bufferedblockcipher/BcPaddedBufferedBlockCipherCustomPaddingTestFile.java")
                .withChecks(this)
                .withClassPath(BouncyCastleJars.JARS)
                .verifyIssues();
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes) {
        /**
         * Optimally, we shouldn't have these direct detections of engines, as they appear in the
         * depending detection rules
         */
        if (findingId == 0 || findingId == 1) {
            return;
        }

        /*
         * Detection Store
         */

        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
        assertThat(value0).isInstanceOf(ValueAction.class);
        assertThat(value0.asString()).isEqualTo("PaddedBuffered(PKCS7)");

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_1 =
                getStoreOfValueType(OperationMode.class, detectionStore.getChildren());
        assertThat(store_1.getDetectionValues()).hasSize(1);
        assertThat(store_1.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        IValue<Tree> value0_1 = store_1.getDetectionValues().get(0);
        assertThat(value0_1).isInstanceOf(OperationMode.class);
        assertThat(value0_1.asString()).isEqualTo("1");

        List<DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext>> stores =
                getStoresOfValueType(ValueAction.class, detectionStore.getChildren());
        /*
         * Expect 2 ValueActions:
         * 1 - CBC
         * 2 - AES (as child of CBC)
         */
        assertThat(stores).hasSize(2);

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_2 = stores.get(0);
        assertThat(store_2.getDetectionValues()).hasSize(1);
        assertThat(store_2.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        IValue<Tree> value0_2 = store_2.getDetectionValues().get(0);
        assertThat(value0_2).isInstanceOf(ValueAction.class);
        assertThat(value0_2.asString()).isEqualTo("CBC");

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_2_1 =
                getStoreOfValueType(ValueAction.class, store_2.getChildren());
        assertThat(store_2_1).isNotNull();
        assertThat(store_2_1.getDetectionValues()).hasSize(1);
        assertThat(store_2_1.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        IValue<Tree> value0_2_1 = store_2_1.getDetectionValues().get(0);
        assertThat(value0_2_1).isInstanceOf(ValueAction.class);
        assertThat(value0_2_1.asString()).isEqualTo("AES");

        /*
         * Translation
         */

        assertThat(nodes).hasSize(1);

        // BlockCipher
        INode blockCipherNode = nodes.get(0);
        assertThat(blockCipherNode.getKind()).isEqualTo(BlockCipher.class);
        assertThat(blockCipherNode.getChildren()).hasSize(2);
        assertThat(blockCipherNode.asString()).isEqualTo("AES");

        // Padding under BlockCipher
        INode paddingNode = blockCipherNode.getChildren().get(Padding.class);
        assertThat(paddingNode).isNotNull();
        assertThat(paddingNode.getChildren()).isEmpty();
        assertThat(paddingNode.asString()).isEqualTo("PKCS7");

        // Encrypt under BlockCipher
        INode encryptNode = blockCipherNode.getChildren().get(Encrypt.class);
        assertThat(encryptNode).isNotNull();
        assertThat(encryptNode.getChildren()).isEmpty();
        assertThat(encryptNode.asString()).isEqualTo("ENCRYPT");

        // TODO: finish the translation once we have the correct detection store
    }
}
