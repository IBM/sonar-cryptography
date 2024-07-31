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
import com.ibm.engine.model.CipherAction;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.PrivateKeyContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Key;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.MaskGenerationFunction;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.PrivateKey;
import com.ibm.mapper.model.PublicKey;
import com.ibm.mapper.model.functionality.Decrypt;
import com.ibm.mapper.model.functionality.KeyGeneration;
import com.ibm.mapper.model.padding.OAEP;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.plugins.python.api.PythonCheck;
import org.sonar.plugins.python.api.PythonVisitorContext;
import org.sonar.plugins.python.api.symbols.Symbol;
import org.sonar.plugins.python.api.tree.Tree;
import org.sonar.python.checks.utils.PythonCheckVerifier;

public class CryptographyRSADecryptTest extends TestBase {
    @Test
    void test() {
        PythonCheckVerifier.verify(
                "src/test/files/rules/detection/asymmetric/RSA/CryptographyRSADecryptTestFile.py",
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
        assertThat(value).isInstanceOf(KeySize.class);
        assertThat(value.asString()).isEqualTo("1024");

        DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> algoStore =
                getStoreOfValueType(
                        com.ibm.engine.model.Algorithm.class, detectionStore.getChildren());
        assertThat(algoStore).isNotNull();
        assertThat(algoStore.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        assertThat(algoStore.getDetectionValues()).hasSize(2);

        value = algoStore.getDetectionValues().get(0);
        assertThat(value).isInstanceOf(CipherAction.class);
        assertThat(value.asString()).isEqualTo("PADDING");

        value = algoStore.getDetectionValues().get(1);
        assertThat(value).isInstanceOf(com.ibm.engine.model.Algorithm.class);
        assertThat(value.asString()).isEqualTo("MGF1");

        DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> store =
                getStoreOfValueType(
                        CipherAction.class, algoStore.getChildrenForParameterWithId(0).get());
        assertThat(store).isNotNull();
        assertThat(store.getDetectionValueContext()).isInstanceOf(DigestContext.class);
        assertThat(store.getDetectionValues()).hasSize(1);
        value = store.getDetectionValues().get(0);
        assertThat(value).isInstanceOf(CipherAction.class);
        assertThat(value.asString()).isEqualTo("HASH");

        store =
                getStoreOfValueType(
                        CipherAction.class, algoStore.getChildrenForParameterWithId(1).get());
        // detection store in this case
        assertThat(store).isNotNull();
        assertThat(store.getDetectionValueContext()).isInstanceOf(DigestContext.class);
        assertThat(store.getDetectionValues()).hasSize(1);
        value = store.getDetectionValues().get(0);
        assertThat(value).isInstanceOf(CipherAction.class);
        assertThat(value.asString()).isEqualTo("HASH");

        store = getStoreOfValueType(CipherAction.class, detectionStore.getChildren());
        assertThat(store).isNotNull();
        assertThat(store.getDetectionValueContext()).isInstanceOf(CipherContext.class);
        assertThat(store.getDetectionValues()).hasSize(1);
        value = store.getDetectionValues().get(0);
        assertThat(value).isInstanceOf(CipherAction.class);
        assertThat(value.asString()).isEqualTo("DECRYPT");

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
        assertThat(privateKeyKeyLengthNode.asString()).isEqualTo("1024");

        // Algorithm under PrivateKey
        INode privateKeyAlgorithmNode =
                privateKeyNode.getChildren().get(com.ibm.mapper.model.Algorithm.class);
        assertThat(privateKeyAlgorithmNode).isNotNull();
        assertThat(privateKeyAlgorithmNode.asString()).isEqualTo("RSA");

        // Decrypt under Algorithm under PrivateKey
        INode privateKeyDecryptNode = privateKeyAlgorithmNode.getChildren().get(Decrypt.class);
        assertThat(privateKeyDecryptNode).isNotNull();
        assertThat(privateKeyDecryptNode.asString()).isEqualTo("DECRYPT");

        // KeyGeneration under Algorithm under PrivateKey
        INode privateKeyKeyGenerationNode =
                privateKeyAlgorithmNode.getChildren().get(KeyGeneration.class);
        assertThat(privateKeyKeyGenerationNode).isNotNull();
        assertThat(privateKeyKeyGenerationNode.asString()).isEqualTo("KEYGENERATION");

        // OptimalAsymmetricEncryptionPadding under Algorithm under PrivateKey
        INode privateKeyOaepNode = privateKeyAlgorithmNode.getChildren().get(OAEP.class);
        assertThat(privateKeyOaepNode).isNotNull();
        assertThat(privateKeyOaepNode.asString()).isEqualTo("OAEP");

        // MessageDigest under OptimalAsymmetricEncryptionPadding under Algorithm under PrivateKey
        INode messageDigestNode = privateKeyOaepNode.getChildren().get(MessageDigest.class);
        assertThat(messageDigestNode).isNotNull();
        assertThat(messageDigestNode.asString()).isEqualTo("SHA256");

        // MaskGenerationFunction under OptimalAsymmetricEncryptionPadding under Algorithm under
        // PrivateKey
        INode privateKeyMgfNode =
                privateKeyOaepNode.getChildren().get(MaskGenerationFunction.class);
        assertThat(privateKeyMgfNode).isNotNull();
        assertThat(privateKeyMgfNode.asString()).isEqualTo("MGF1");

        // MessageDigest under MaskGenerationFunction under OptimalAsymmetricEncryptionPadding under
        // Algorithm under PrivateKey
        messageDigestNode = privateKeyMgfNode.getChildren().get(MessageDigest.class);
        assertThat(messageDigestNode).isNotNull();
        assertThat(messageDigestNode.asString()).isEqualTo("SHA256");

        // PublicKey
        INode publicKeyNode = nodes.get(1);
        assertThat(publicKeyNode)
                .isInstanceOfAny(PublicKey.class, Key.class); // Special case because of .deepCopy
        assertThat(publicKeyNode.getChildren()).hasSize(2);

        // KeyLength under PublicKey
        INode publicKeyKeyLengthNode = publicKeyNode.getChildren().get(KeyLength.class);
        assertThat(publicKeyKeyLengthNode).isNotNull();
        assertThat(publicKeyKeyLengthNode.asString()).isEqualTo("1024");

        // Algorithm under PublicKey
        INode publicKeyAlgorithmNode =
                publicKeyNode.getChildren().get(com.ibm.mapper.model.Algorithm.class);
        assertThat(publicKeyAlgorithmNode).isNotNull();
        assertThat(publicKeyAlgorithmNode.asString()).isEqualTo("RSA");

        // Decrypt under Algorithm under PublicKey
        INode publicKeyDecryptNode = publicKeyAlgorithmNode.getChildren().get(Decrypt.class);
        assertThat(publicKeyDecryptNode).isNotNull();
        assertThat(publicKeyDecryptNode.asString()).isEqualTo("DECRYPT");

        // KeyGeneration under Algorithm under PublicKey
        INode publicKeyKeyGenerationNode =
                publicKeyAlgorithmNode.getChildren().get(KeyGeneration.class);
        assertThat(publicKeyKeyGenerationNode).isNotNull();
        assertThat(publicKeyKeyGenerationNode.asString()).isEqualTo("KEYGENERATION");

        // OptimalAsymmetricEncryptionPadding under Algorithm under PublicKey
        INode publicKeyOaepNode = publicKeyAlgorithmNode.getChildren().get(OAEP.class);
        assertThat(publicKeyOaepNode).isNotNull();
        assertThat(publicKeyOaepNode.asString()).isEqualTo("OAEP");

        // MessageDigest under OptimalAsymmetricEncryptionPadding under Algorithm under PublicKey
        messageDigestNode = publicKeyOaepNode.getChildren().get(MessageDigest.class);
        assertThat(messageDigestNode).isNotNull();
        assertThat(messageDigestNode.asString()).isEqualTo("SHA256");

        // MaskGenerationFunction under OptimalAsymmetricEncryptionPadding under Algorithm under
        // PublicKey
        INode publicKeyMgfNode = publicKeyOaepNode.getChildren().get(MaskGenerationFunction.class);
        assertThat(publicKeyMgfNode).isNotNull();
        assertThat(publicKeyMgfNode.asString()).isEqualTo("MGF1");

        // MessageDigest under MaskGenerationFunction under OptimalAsymmetricEncryptionPadding under
        // Algorithm under PublicKey
        messageDigestNode = publicKeyMgfNode.getChildren().get(MessageDigest.class);
        assertThat(messageDigestNode).isNotNull();
        assertThat(messageDigestNode.asString()).isEqualTo("SHA256");
    }
}
