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
package com.ibm.plugin.rules.detection.fernet;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.CipherAction;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.context.PrivateKeyContext;
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.PrivateKey;
import com.ibm.mapper.model.functionality.Decrypt;
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

public class PycaFernetDecryptTest extends TestBase {
    @Test
    void test() {
        PythonCheckVerifier.verify(
                "src/test/files/rules/detection/fernet/CryptographyFernetDecryptTestFile.py", this);
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

        List<DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext>> stores =
                getStoresOfValueType(CipherAction.class, detectionStore.getChildren());
        assertThat(stores.size()).isEqualTo(1); //  DECRYPT

        /*
         * Translation
         */
        assertThat(nodes).hasSize(1);

        // PrivateKey
        INode privateKeyNode = nodes.get(0);
        assertThat(privateKeyNode).isInstanceOf(PrivateKey.class);
        assertThat(privateKeyNode.getChildren()).hasSize(1);
        assertThat(privateKeyNode.asString()).isEqualTo("Fernet");

        // Algorithm under PrivateKey
        INode privateKeyAlgorithmNode = privateKeyNode.getChildren().get(Algorithm.class);
        assertThat(privateKeyAlgorithmNode).isNotNull();
        assertThat(privateKeyAlgorithmNode.asString()).isEqualTo("Fernet");

        // KeyGeneration under Algorithm under PrivateKey
        INode privateKeyGenerationNode =
                privateKeyAlgorithmNode.getChildren().get(KeyGeneration.class);
        assertThat(privateKeyGenerationNode).isNotNull();
        assertThat(privateKeyGenerationNode.asString()).isEqualTo("KEYGENERATION");

        // Decrypt under Algorithm under PrivateKey
        INode privateKeyDecryptNode = privateKeyAlgorithmNode.getChildren().get(Decrypt.class);
        assertThat(privateKeyDecryptNode).isNotNull();
        assertThat(privateKeyDecryptNode.asString()).isEqualTo("DECRYPT");
    }
}
