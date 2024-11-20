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
import com.ibm.engine.model.BlockSize;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.OperationMode;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Mode;
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

class BcG3413CFBBlockCipherTest extends TestBase {
    @Disabled("Duplication of te OperationMode creates duplicated translated nodes")
    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile(
                        "src/test/files/rules/detection/bc/blockcipher/BcG3413CFBBlockCipherTestFile.java")
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
        assertThat(value0.asString()).isEqualTo("GOST R 34.12-2015|CFB");

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_1 =
                getStoreOfValueType(OperationMode.class, detectionStore.getChildren());
        assertThat(store_1.getDetectionValues()).hasSize(1);
        assertThat(store_1.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        IValue<Tree> value0_1 = store_1.getDetectionValues().get(0);
        assertThat(value0_1).isInstanceOf(OperationMode.class);
        assertThat(value0_1.asString()).isEqualTo("1");

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_2 =
                getStoreOfValueType(BlockSize.class, detectionStore.getChildren());
        assertThat(store_2.getDetectionValues()).hasSize(1);
        assertThat(store_2.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        IValue<Tree> value0_2 = store_2.getDetectionValues().get(0);
        assertThat(value0_2).isInstanceOf(BlockSize.class);
        assertThat(value0_2.asString()).isEqualTo("128");

        /* TODO: optimally, this shouldn't be detected */
        /* DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_3 =
                getStoreOfValueType(OperationMode.class, detectionStore.getChildren());
        assertThat(store_3.getDetectionValues()).hasSize(1);
        assertThat(store_3.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        IValue<Tree> value0_3 = store_3.getDetectionValues().get(0);
        assertThat(value0_3).isInstanceOf(OperationMode.class);
        assertThat(value0_3.asString()).isEqualTo("1"); */

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_4 =
                getStoreOfValueType(ValueAction.class, detectionStore.getChildren());
        assertThat(store_4.getDetectionValues()).hasSize(1);
        assertThat(store_4.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        IValue<Tree> value0_4 = store_4.getDetectionValues().get(0);
        assertThat(value0_4).isInstanceOf(ValueAction.class);
        assertThat(value0_4.asString()).isEqualTo("GOST R 34.12-2015");

        /* TODO: optimally, this shouldn't be detected */
        /* DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_4_1 =
                getStoreOfValueType(OperationMode.class, store_4.getChildren());
        assertThat(store_4_1.getDetectionValues()).hasSize(1);
        assertThat(store_4_1.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        IValue<Tree> value0_4_1 = store_4_1.getDetectionValues().get(0);
        assertThat(value0_4_1).isInstanceOf(OperationMode.class);
        assertThat(value0_4_1.asString()).isEqualTo("1"); */

        /*
         * Translation
         */

        assertThat(nodes).hasSize(1);

        // BlockCipher
        INode blockCipherNode = nodes.get(0);
        assertThat(blockCipherNode.getKind()).isEqualTo(BlockCipher.class);
        assertThat(blockCipherNode.getChildren()).hasSize(3);
        assertThat(blockCipherNode.asString()).isEqualTo("GOST R 34.12-2015");

        // Mode under BlockCipher
        INode modeNode = blockCipherNode.getChildren().get(Mode.class);
        assertThat(modeNode).isNotNull();
        assertThat(modeNode.getChildren()).isEmpty();
        assertThat(modeNode.asString()).isEqualTo("CFB");

        // BlockSize under BlockCipher
        INode blockSizeNode =
                blockCipherNode.getChildren().get(com.ibm.mapper.model.BlockSize.class);
        assertThat(blockSizeNode).isNotNull();
        assertThat(blockSizeNode.getChildren()).isEmpty();
        assertThat(blockSizeNode.asString()).isEqualTo("128");

        // Encrypt under BlockCipher
        INode encryptNode = blockCipherNode.getChildren().get(Encrypt.class);
        assertThat(encryptNode).isNotNull();
        assertThat(encryptNode.getChildren()).isEmpty();
        assertThat(encryptNode.asString()).isEqualTo("ENCRYPT");
    }
}
