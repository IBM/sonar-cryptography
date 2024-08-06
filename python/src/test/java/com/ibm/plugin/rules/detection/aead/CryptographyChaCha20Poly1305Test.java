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
package com.ibm.plugin.rules.detection.aead;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.CipherAction;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.SecretKeyContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.SecretKey;
import com.ibm.mapper.model.StreamCipher;
import com.ibm.mapper.model.functionality.Decrypt;
import com.ibm.mapper.model.functionality.Encrypt;
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

public class CryptographyChaCha20Poly1305Test extends TestBase {
    @Test
    void test() {
        PythonCheckVerifier.verify(
                "src/test/files/rules/detection/aead/CryptographyChaCha20Poly1305TestFile.py",
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
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(SecretKeyContext.class);
        assertThat(value).isInstanceOf(KeyAction.class);
        assertThat(value.asString()).isEqualTo("GENERATION");

        assertThat(detectionStore.getChildren()).hasSize(2);

        DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> store =
                detectionStore.getChildren().get(0);
        IValue<Tree> decryptValue = store.getDetectionValues().get(0);
        assertThat(store.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        assertThat(decryptValue).isInstanceOf(CipherAction.class);
        assertThat(decryptValue.asString()).isEqualTo("ENCRYPT");

        store = detectionStore.getChildren().get(1);
        IValue<Tree> encryptValue = store.getDetectionValues().get(0);
        assertThat(store.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        assertThat(encryptValue).isInstanceOf(CipherAction.class);
        assertThat(encryptValue.asString()).isEqualTo("DECRYPT");

        /*
         * Translation
         */
        assertThat(nodes).hasSize(1);

        // SecretKey
        INode secretKeyNode = nodes.get(0);
        assertThat(secretKeyNode).isInstanceOf(SecretKey.class);
        assertThat(secretKeyNode.getChildren()).hasSize(1);

        // StreamCipher under SecretKey
        INode streamCipherNode = secretKeyNode.getChildren().get(StreamCipher.class);
        assertThat(streamCipherNode).isNotNull();
        assertThat(streamCipherNode.asString()).isEqualTo("ChaCha20");

        // Decrypt under StreamCipher
        INode decryptNode = streamCipherNode.getChildren().get(Decrypt.class);
        assertThat(decryptNode).isNotNull();
        assertThat(decryptNode.asString()).isEqualTo("DECRYPT");

        // Encrypt under StreamCipher
        INode encryptNode = streamCipherNode.getChildren().get(Encrypt.class);
        assertThat(encryptNode).isNotNull();
        assertThat(encryptNode.asString()).isEqualTo("ENCRYPT");

        // Mac under StreamCipher
        INode macNode = streamCipherNode.getChildren().get(Mac.class);
        assertThat(macNode).isNotNull();
        assertThat(macNode.asString()).isEqualTo("Poly1305");

        // KeyGeneration under StreamCipher
        INode keyGenerationNode = streamCipherNode.getChildren().get(KeyGeneration.class);
        assertThat(keyGenerationNode).isNotNull();
        assertThat(keyGenerationNode.asString()).isEqualTo("KEYGENERATION");
    }
}
