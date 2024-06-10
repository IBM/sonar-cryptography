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
package com.ibm.plugin.rules.detection.asymmetric.RSA;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.context.PrivateKeyContext;
import com.ibm.engine.model.context.PublicKeyContext;
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Key;
import com.ibm.mapper.model.PrivateKey;
import com.ibm.mapper.model.PublicKey;
import com.ibm.mapper.model.functionality.KeyGeneration;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.plugins.python.api.PythonCheck;
import org.sonar.plugins.python.api.PythonVisitorContext;
import org.sonar.plugins.python.api.symbols.Symbol;
import org.sonar.plugins.python.api.tree.Tree;
import org.sonar.python.checks.utils.PythonCheckVerifier;

public class CryptographyRSANumbersTest extends TestBase {
    @Test
    void test() {
        PythonCheckVerifier.verify(
                "src/test/files/rules/detection/asymmetric/RSA/CryptographyRSANumbersTestFile.py",
                this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> detectionStore,
            @Nonnull List<INode> nodes) {
        /*
         * Detection Store
         */
        assertThat(detectionStore.getDetectionValues()).hasSize(1);

        // Public Key Context
        if (findingId == 0) {
            IValue<Tree> publicKeyContextValue = detectionStore.getDetectionValues().get(0);
            assertThat(detectionStore.getDetectionValueContext())
                    .isInstanceOf(PublicKeyContext.class);
            assertThat(publicKeyContextValue).isInstanceOf(KeyAction.class);
            assertThat(publicKeyContextValue.asString()).isEqualTo("GENERATION");
        }

        // Private Key Context
        if (findingId == 1) {
            IValue<Tree> privateKeyContextValue = detectionStore.getDetectionValues().get(0);
            assertThat(detectionStore.getDetectionValueContext())
                    .isInstanceOf(PrivateKeyContext.class);
            assertThat(privateKeyContextValue).isInstanceOf(KeyAction.class);
            assertThat(privateKeyContextValue.asString()).isEqualTo("GENERATION");
        }

        /*
         * Translation
         */
        assertThat(nodes).hasSize(1);

        if (findingId == 0) {
            // Public Key
            INode publicKeyNode = nodes.get(0);
            assertThat(publicKeyNode).isInstanceOf(PublicKey.class);
            assertThat(publicKeyNode.getChildren()).hasSize(1);

            // Algorithm under Public Key
            INode publicKeyAlgorithmNode = publicKeyNode.getChildren().get(Algorithm.class);
            assertThat(publicKeyAlgorithmNode).isNotNull();
            assertThat(publicKeyAlgorithmNode.asString()).isEqualTo("RSA");

            // Key Generation under Algorithm under Public Key
            INode publicKeyKeyGenerationNode =
                    publicKeyAlgorithmNode.getChildren().get(KeyGeneration.class);
            assertThat(publicKeyKeyGenerationNode).isNotNull();
            assertThat(publicKeyKeyGenerationNode.asString()).isEqualTo("KEYGENERATION");
        }

        if (findingId == 1) {
            // Private Key
            INode privateKeyNode = nodes.get(0);
            assertThat(privateKeyNode).isInstanceOfAny(PrivateKey.class, Key.class);
            assertThat(privateKeyNode.getChildren()).hasSize(1);

            // Algorithm under Private Key
            INode privateKeyAlgorithmNode = privateKeyNode.getChildren().get(Algorithm.class);
            assertThat(privateKeyAlgorithmNode).isNotNull();
            assertThat(privateKeyAlgorithmNode.asString()).isEqualTo("RSA");

            // Key Generation under Algorithm under Private Key
            INode privateKeyKeyGenerationNode =
                    privateKeyAlgorithmNode.getChildren().get(KeyGeneration.class);
            assertThat(privateKeyKeyGenerationNode).isNotNull();
            assertThat(privateKeyKeyGenerationNode.asString()).isEqualTo("KEYGENERATION");
        }
    }
}
