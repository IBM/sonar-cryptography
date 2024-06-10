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
package com.ibm.plugin.rules.detection.jca.keyfactory;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Key;
import com.ibm.mapper.model.KeyLength;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

class JcaKeyFactoryGenerateTest extends TestBase {

    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile(
                        "src/test/files/rules/detection/jca/keyfactory/JcaKeyFactoryGenerateTestFile.java")
                .withChecks(this)
                .verifyIssues();
    }

    /**
     * DEBUG [detectionStore] (KeyContext<>, Algorithm) RSA DEBUG [detectionStore] └─
     * (PrivateKeyContext, KeyAction) GENERATION DEBUG [detectionStore] └─ (KeyContext<DH>,
     * KeySize<bit>) 128 DEBUG [translation] (Key) RSA DEBUG [translation] └─ (KeyLength) 128 DEBUG
     * [translation] └─ (Algorithm) RSA DEBUG [translation] └─ (KeyLength) 2048
     */
    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes) {
        /*
         * Detection Store
         */
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        IValue<Tree> value = detectionStore.getDetectionValues().get(0);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(KeyContext.class);
        assertThat(value).isInstanceOf(Algorithm.class);
        assertThat(value.asString()).isEqualTo("RSA");

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store =
                getStoreOfValueType(KeyAction.class, detectionStore.getChildren());
        assertThat(store).isNotNull();
        assertThat(store.getDetectionValueContext()).isInstanceOf(KeyContext.class);
        assertThat(store.getDetectionValues()).hasSize(1);
        value = store.getDetectionValues().get(0);
        assertThat(value).isInstanceOf(KeyAction.class);
        assertThat(value.asString()).isEqualTo("GENERATION");

        store = getStoreOfValueType(KeySize.class, store.getChildren());
        assertThat(store).isNotNull();
        assertThat(store.getDetectionValueContext()).isInstanceOf(KeyContext.class);
        assertThat(((KeyContext) store.getDetectionValueContext()).kind())
                .isEqualTo(KeyContext.Kind.DH);
        assertThat(store.getDetectionValues()).hasSize(1);
        value = store.getDetectionValues().get(0);
        assertThat(value).isInstanceOf(KeySize.class);
        assertThat(value.asString()).isEqualTo("4096");

        /*
         * Translation
         */
        assertThat(nodes).hasSize(1);
        INode node = nodes.get(0);
        assertThat(node).isInstanceOf(Key.class);
        assertThat(node.asString()).isEqualTo("RSA");

        INode keyLength = node.getChildren().get(KeyLength.class);
        assertThat(keyLength).isNotNull();
        assertThat(keyLength.asString()).isEqualTo("4096");

        INode algorithm = node.getChildren().get(com.ibm.mapper.model.PublicKeyEncryption.class);
        assertThat(algorithm).isNotNull();
        assertThat(algorithm.asString()).isEqualTo("RSA");

        INode defaultKeyLength = algorithm.getChildren().get(KeyLength.class);
        assertThat(defaultKeyLength).isNotNull();
        assertThat(defaultKeyLength.asString()).isEqualTo("2048");
    }
}
