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
package com.ibm.plugin.rules.detection.bc.blockcipher;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.OperationMode;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.functionality.Decrypt;
import com.ibm.mapper.model.functionality.Encrypt;
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

class BcCBCBlockCipherTest extends TestBase {
    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile(
                        "src/test/files/rules/detection/bc/blockcipher/BcCBCBlockCipherTestFile.java")
                .withChecks(this)
                .withClassPath(BouncyCastleJars.JARS)
                .verifyIssues();
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes) {
        /*
         * Optimally, we shouldn't have these direct detections of engines, as they appear in
         * the depending detection rules
         */
        if (findingId == 0 || findingId == 2) {
            return;
        }

        /*
         * Detection Store
         */
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
        assertThat(value0).isInstanceOf(ValueAction.class);
        assertThat(value0.asString()).isEqualTo("CBCBlockCipher");

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_1 =
                getStoreOfValueType(OperationMode.class, detectionStore.getChildren());
        assertThat(store_1).isNotNull();
        assertThat(store_1.getDetectionValues()).hasSize(1);
        assertThat(store_1.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        IValue<Tree> value0_1 = store_1.getDetectionValues().get(0);
        assertThat(value0_1).isInstanceOf(OperationMode.class);
        assertThat(value0_1.asString()).isEqualTo(findingId == 1 ? "1" : "0");

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_2 =
                getStoreOfValueType(ValueAction.class, detectionStore.getChildren());
        assertThat(store_2).isNotNull();
        assertThat(store_2.getDetectionValues()).hasSize(1);
        assertThat(store_2.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        IValue<Tree> value0_2 = store_2.getDetectionValues().get(0);
        assertThat(value0_2).isInstanceOf(ValueAction.class);
        assertThat(value0_2.asString()).isEqualTo(findingId == 1 ? "AESFastEngine" : "AESEngine");

        // Optimally, this shouldn't be detected
        //
        // DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_2_1 =
        //         getStoreOfValueType(OperationMode.class, store_2.getChildren());
        // assertThat(store_2_1.getDetectionValues()).hasSize(1);
        // assertThat(store_2_1.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        // IValue<Tree> value0_2_1 = store_2_1.getDetectionValues().get(0);
        // assertThat(value0_2_1).isInstanceOf(OperationMode.class);
        // assertThat(value0_2_1.asString()).isEqualTo(findingId == 1 ? "1" : "0");

        /*
         * Translation
         */
        assertThat(nodes).hasSize(1);
        // BlockCipher
        INode blockCipherNode1 = nodes.get(0);
        assertThat(blockCipherNode1.getKind()).isEqualTo(BlockCipher.class);
        assertThat(blockCipherNode1.getChildren()).hasSize(4);
        assertThat(blockCipherNode1.asString()).isEqualTo("AES-CBC");

        // Decrypt under BlockCipher
        INode decryptNode =
                blockCipherNode1.getChildren().get(findingId == 1 ? Encrypt.class : Decrypt.class);
        assertThat(decryptNode).isNotNull();
        assertThat(decryptNode.getChildren()).isEmpty();
        assertThat(decryptNode.asString()).isEqualTo(findingId == 1 ? "ENCRYPT" : "DECRYPT");

        // Mode under BlockCipher
        INode modeNode1 = blockCipherNode1.getChildren().get(Mode.class);
        assertThat(modeNode1).isNotNull();
        assertThat(modeNode1.getChildren()).isEmpty();
        assertThat(modeNode1.asString()).isEqualTo("CBC");
    }
}
