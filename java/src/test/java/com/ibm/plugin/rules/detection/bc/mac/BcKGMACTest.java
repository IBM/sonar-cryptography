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
package com.ibm.plugin.rules.detection.bc.mac;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.MacSize;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.MacContext;
import com.ibm.mapper.model.AuthenticatedEncryption;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.TagLength;
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

class BcKGMACTest extends TestBase {
    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile("src/test/files/rules/detection/bc/mac/BcKGMacTestFile.java")
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
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(MacContext.class);
        IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
        assertThat(value0).isInstanceOf(ValueAction.class);
        assertThat(value0.asString()).isEqualTo("KGMac");

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_1 =
                getStoreOfValueType(MacSize.class, detectionStore.getChildren());
        assertThat(store_1.getDetectionValues()).hasSize(1);
        assertThat(store_1.getDetectionValueContext()).isInstanceOf(MacContext.class);
        IValue<Tree> value0_1 = store_1.getDetectionValues().get(0);
        assertThat(value0_1).isInstanceOf(MacSize.class);
        assertThat(value0_1.asString()).isEqualTo("128");

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_2 =
                getStoreOfValueType(ValueAction.class, detectionStore.getChildren());
        assertThat(store_2.getDetectionValues()).hasSize(1);
        assertThat(store_2.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        IValue<Tree> value0_2 = store_2.getDetectionValues().get(0);
        assertThat(value0_2).isInstanceOf(ValueAction.class);
        assertThat(value0_2.asString()).isEqualTo("KGCMBlockCipher");

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_2_1 =
                getStoreOfValueType(ValueAction.class, store_2.getChildren());
        assertThat(store_2_1.getDetectionValues()).hasSize(1);
        assertThat(store_2_1.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        IValue<Tree> value0_2_1 = store_2_1.getDetectionValues().get(0);
        assertThat(value0_2_1).isInstanceOf(ValueAction.class);
        assertThat(value0_2_1.asString()).isEqualTo("DSTU7624Engine");

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_2_1_1 =
                getStoreOfValueType(com.ibm.engine.model.BlockSize.class, store_2_1.getChildren());
        assertThat(store_2_1_1.getDetectionValues()).hasSize(1);
        assertThat(store_2_1_1.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        IValue<Tree> value0_2_1_1 = store_2_1_1.getDetectionValues().get(0);
        assertThat(value0_2_1_1).isInstanceOf(com.ibm.engine.model.BlockSize.class);
        assertThat(value0_2_1_1.asString()).isEqualTo("64");

        /*
         * Translation
         */

        assertThat(nodes).hasSize(1);

        // Mac
        INode macNode = nodes.get(0);
        assertThat(macNode.getKind()).isEqualTo(Mac.class);
        assertThat(macNode.getChildren()).hasSize(4);
        assertThat(macNode.asString()).isEqualTo("Kalyna");

        // TagLength under Mac
        INode tagLengthNode = macNode.getChildren().get(TagLength.class);
        assertThat(tagLengthNode).isNotNull();
        assertThat(tagLengthNode.getChildren()).isEmpty();
        assertThat(tagLengthNode.asString()).isEqualTo("128");

        // Mode under Mac
        INode modeNode = macNode.getChildren().get(Mode.class);
        assertThat(modeNode).isNotNull();
        assertThat(modeNode.getChildren()).isEmpty();
        assertThat(modeNode.asString()).isEqualTo("GMAC");

        // AuthenticatedEncryption under Mac
        INode authenticatedEncryptionNode =
                macNode.getChildren().get(AuthenticatedEncryption.class);
        assertThat(authenticatedEncryptionNode).isNotNull();
        assertThat(authenticatedEncryptionNode.getChildren()).hasSize(2);
        assertThat(authenticatedEncryptionNode.asString()).isEqualTo("Kalyna-64");

        // BlockSize under AuthenticatedEncryption under Mac
        INode blockSizeNode = authenticatedEncryptionNode.getChildren().get(BlockSize.class);
        assertThat(blockSizeNode).isNotNull();
        assertThat(blockSizeNode.getChildren()).isEmpty();
        assertThat(blockSizeNode.asString()).isEqualTo("64");

        // Mode under AuthenticatedEncryption under Mac
        INode modeNode1 = authenticatedEncryptionNode.getChildren().get(Mode.class);
        assertThat(modeNode1).isNotNull();
        assertThat(modeNode1.getChildren()).isEmpty();
        assertThat(modeNode1.asString()).isEqualTo("GCM");

        // Tag under Mac
        INode tagNode = macNode.getChildren().get(Tag.class);
        assertThat(tagNode).isNotNull();
        assertThat(tagNode.getChildren()).isEmpty();
        assertThat(tagNode.asString()).isEqualTo("TAG");
    }
}
