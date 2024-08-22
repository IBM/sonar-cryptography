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
package com.ibm.plugin.rules.detection.asymmetric.DiffieHellman;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.context.PrivateKeyContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Key;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.PrivateKey;
import com.ibm.mapper.model.PublicKey;
import com.ibm.mapper.model.functionality.KeyGeneration;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.sonar.plugins.python.api.PythonCheck;
import org.sonar.plugins.python.api.PythonVisitorContext;
import org.sonar.plugins.python.api.symbols.Symbol;
import org.sonar.plugins.python.api.tree.Tree;
import org.sonar.python.checks.utils.PythonCheckVerifier;

public class PycaDiffieHellmanGenerateTest extends TestBase {

    @Disabled // TODO: reenable once this
    // (https://github.ibm.com/CryptoDiscovery/sonar-java-crypto-plugin/issues/34#issuecomment-74401655) is fixed
    @Test
    void test() {
        PythonCheckVerifier.verify(
                "src/test/files/rules/detection/asymmetric/DiffieHellman/CryptographyDiffieHellmanGenerateTestFile.py",
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
        IValue<Tree> value = detectionStore.getDetectionValues().get(0);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(PrivateKeyContext.class);
        assertThat(value).isInstanceOf(KeyAction.class);
        assertThat(value.asString()).isEqualTo("GENERATION");

        /*
         * Translation
         */
        assertThat(nodes).hasSize(2);

        // PrivateKey
        INode privateKeyNode = nodes.get(0);
        assertThat(privateKeyNode).isInstanceOf(PrivateKey.class);
        assertThat(privateKeyNode.getChildren()).hasSize(2);

        // KeyLength under PrivateKey
        INode privateKeyKeyLengthNode = privateKeyNode.getChildren().get(KeyLength.class);
        assertThat(privateKeyKeyLengthNode).isNotNull();
        assertThat(privateKeyKeyLengthNode.asString()).isEqualTo("2048");

        // Algorithm under PrivateKey
        INode privateKeyAlgorithmNode = privateKeyNode.getChildren().get(Algorithm.class);
        assertThat(privateKeyAlgorithmNode).isNotNull();
        assertThat(privateKeyAlgorithmNode.asString()).isEqualTo("DH");

        // KeyGeneration under Algorithm under PrivateKey
        INode privateKeyKeyGenerationNode =
                privateKeyAlgorithmNode.getChildren().get(KeyGeneration.class);
        assertThat(privateKeyKeyGenerationNode).isNotNull();
        assertThat(privateKeyKeyGenerationNode.asString()).isEqualTo("KEYGENERATION");

        // KeyLength under Algorithm under PrivateKey
        INode privateKeyAlgorithmKeyLengthNode =
                privateKeyAlgorithmNode.getChildren().get(KeyLength.class);
        assertThat(privateKeyAlgorithmKeyLengthNode).isNotNull();
        assertThat(privateKeyAlgorithmKeyLengthNode.asString()).isEqualTo("2048");

        // PublicKey
        INode publicKeyNode = nodes.get(1);
        assertThat(publicKeyNode).isInstanceOfAny(PublicKey.class, Key.class);
        assertThat(publicKeyNode.getChildren()).hasSize(2);

        // KeyLength under PublicKey
        INode publicKeyKeyLengthNode = publicKeyNode.getChildren().get(KeyLength.class);
        assertThat(publicKeyKeyLengthNode).isNotNull();
        assertThat(publicKeyKeyLengthNode.asString()).isEqualTo("2048");

        // Algorithm under PublicKey
        INode publicKeyAlgorithmNode = publicKeyNode.getChildren().get(Algorithm.class);
        assertThat(publicKeyAlgorithmNode).isNotNull();
        assertThat(publicKeyAlgorithmNode.asString()).isEqualTo("DH");

        // KeyGeneration under Algorithm under PublicKey
        INode publicKeyKeyGenerationNode =
                publicKeyAlgorithmNode.getChildren().get(KeyGeneration.class);
        assertThat(publicKeyKeyGenerationNode).isNotNull();
        assertThat(publicKeyKeyGenerationNode.asString()).isEqualTo("KEYGENERATION");

        // KeyLength under Algorithm under PublicKey
        INode publicKeyAlgorithmKeyLengthNode =
                publicKeyAlgorithmNode.getChildren().get(KeyLength.class);
        assertThat(publicKeyAlgorithmKeyLengthNode).isNotNull();
        assertThat(publicKeyAlgorithmKeyLengthNode.asString()).isEqualTo("2048");
    }
}
