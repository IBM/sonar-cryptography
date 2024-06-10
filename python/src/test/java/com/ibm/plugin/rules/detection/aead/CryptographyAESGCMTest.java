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
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.SecretKeyContext;
import com.ibm.mapper.model.AuthenticatedEncryption;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.SecretKey;
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

public class CryptographyAESGCMTest extends TestBase {
    @Test
    void test() {
        PythonCheckVerifier.verify(
                "src/test/files/rules/detection/aead/CryptographyAESGCMTestFile.py", this);
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
        assertThat(value).isInstanceOf(KeySize.class);
        assertThat(value.asString()).isEqualTo("128");

        assertThat(detectionStore.getChildren()).hasSize(2);

        DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> store =
                detectionStore.getChildren().get(0);
        IValue<Tree> decryptValue = store.getDetectionValues().get(0);
        assertThat(store.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        assertThat(decryptValue).isInstanceOf(CipherAction.class);
        assertThat(decryptValue.asString()).isEqualTo("DECRYPT");

        store = detectionStore.getChildren().get(1);
        IValue<Tree> encryptValue = store.getDetectionValues().get(0);
        assertThat(store.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        assertThat(encryptValue).isInstanceOf(CipherAction.class);
        assertThat(encryptValue.asString()).isEqualTo("ENCRYPT");

        /*
         * Translation
         */
        assertThat(nodes).hasSize(1);

        // SecretKey
        INode secretKeyNode = nodes.get(0);
        assertThat(secretKeyNode).isInstanceOf(SecretKey.class);
        assertThat(secretKeyNode.getChildren()).hasSize(2);

        // KeyLength under SecretKey
        INode keyLengthNode = secretKeyNode.getChildren().get(KeyLength.class);
        assertThat(keyLengthNode).isNotNull();
        assertThat(keyLengthNode.asString()).isEqualTo("128");

        // AuthenticatedEncryption under SecretKey
        INode authEncryptionNode = secretKeyNode.getChildren().get(AuthenticatedEncryption.class);
        assertThat(authEncryptionNode).isNotNull();
        assertThat(authEncryptionNode.asString()).isEqualTo("AES");

        // Mode under AuthenticatedEncryption
        INode modeNode = authEncryptionNode.getChildren().get(Mode.class);
        assertThat(modeNode).isNotNull();
        assertThat(modeNode.asString()).isEqualTo("GCM");

        // Decrypt under AuthenticatedEncryption
        INode decryptNode = authEncryptionNode.getChildren().get(Decrypt.class);
        assertThat(decryptNode).isNotNull();
        assertThat(decryptNode.asString()).isEqualTo("DECRYPT");

        // Encrypt under AuthenticatedEncryption
        INode encryptNode = authEncryptionNode.getChildren().get(Encrypt.class);
        assertThat(encryptNode).isNotNull();
        assertThat(encryptNode.asString()).isEqualTo("ENCRYPT");

        // KeyGeneration under AuthenticatedEncryption
        INode keyGenerationNode = authEncryptionNode.getChildren().get(KeyGeneration.class);
        assertThat(keyGenerationNode).isNotNull();
        assertThat(keyGenerationNode.asString()).isEqualTo("KEYGENERATION");

        // KeyLength under AuthenticatedEncryption
        keyLengthNode = authEncryptionNode.getChildren().get(KeyLength.class);
        assertThat(keyLengthNode).isNotNull();
        assertThat(keyLengthNode.asString()).isEqualTo("128");
    }
}
