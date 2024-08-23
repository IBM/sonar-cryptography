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
import com.ibm.engine.model.SignatureAction;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.PrivateKeyContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Key;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.MaskGenerationFunction;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.PrivateKey;
import com.ibm.mapper.model.ProbabilisticSignatureScheme;
import com.ibm.mapper.model.PublicKey;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.functionality.KeyGeneration;
import com.ibm.mapper.model.functionality.Sign;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.plugins.python.api.PythonCheck;
import org.sonar.plugins.python.api.PythonVisitorContext;
import org.sonar.plugins.python.api.symbols.Symbol;
import org.sonar.plugins.python.api.tree.Tree;
import org.sonar.python.checks.utils.PythonCheckVerifier;

public class PycaRSASign1Test extends TestBase {
    @Test
    void test() {
        PythonCheckVerifier.verify(
                "src/test/files/rules/detection/asymmetric/RSA/CryptographyRSASign1TestFile.py",
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
        assertThat(value.asString()).isEqualTo("2048");

        DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> store =
                getStoreOfValueType(
                        com.ibm.engine.model.Algorithm.class, detectionStore.getChildren());
        assertThat(store).isNotNull();
        assertThat(store.getDetectionValueContext()).isInstanceOf(SignatureContext.class);
        assertThat(store.getDetectionValues()).hasSize(2);

        value = store.getDetectionValues().get(0);
        assertThat(value).isInstanceOf(SignatureAction.class);
        assertThat(value.asString()).isEqualTo("PADDING");

        value = store.getDetectionValues().get(1);
        assertThat(value).isInstanceOf(com.ibm.engine.model.Algorithm.class);
        assertThat(value.asString()).isEqualTo("MGF1");

        store =
                getStoreOfValueType(
                        CipherAction.class,
                        detectionStore.getChildren().get(0).getChildrenForParameterWithId(1).get());
        assertThat(store).isNotNull();
        assertThat(store.getDetectionValueContext()).isInstanceOf(DigestContext.class);
        assertThat(store.getDetectionValues()).hasSize(1);
        value = store.getDetectionValues().get(0);
        assertThat(value).isInstanceOf(CipherAction.class);
        assertThat(value.asString()).isEqualTo("HASH");

        store =
                getStoreOfValueType(
                        CipherAction.class,
                        detectionStore.getChildren().get(0).getChildrenForParameterWithId(2).get());
        // detection store in this case
        assertThat(store).isNotNull();
        assertThat(store.getDetectionValueContext()).isInstanceOf(DigestContext.class);
        assertThat(store.getDetectionValues()).hasSize(1);
        value = store.getDetectionValues().get(0);
        assertThat(value).isInstanceOf(CipherAction.class);
        assertThat(value.asString()).isEqualTo("HASH");

        store = getStoreOfValueType(SignatureAction.class, detectionStore.getChildren());
        assertThat(store).isNotNull();
        assertThat(store.getDetectionValueContext()).isInstanceOf(SignatureContext.class);
        assertThat(store.getDetectionValues()).hasSize(1);
        value = store.getDetectionValues().get(0);
        assertThat(value).isInstanceOf(SignatureAction.class);
        assertThat(value.asString()).isEqualTo("SIGN");

        /*
         * Translation
         */
        assertThat(nodes).hasSize(2);

        // PrivateKey
        INode privateKeyNode = nodes.get(0);
        assertThat(privateKeyNode).isInstanceOf(PrivateKey.class);
        assertThat(privateKeyNode).isNotNull();
        assertThat(privateKeyNode.asString()).isEqualTo("RSA");
        assertThat(privateKeyNode.getChildren()).hasSize(3); // Three children detected

        // KeyLength under PrivateKey
        INode privateKeyKeyLengthNode = privateKeyNode.getChildren().get(KeyLength.class);
        assertThat(privateKeyKeyLengthNode).isNotNull();
        assertThat(privateKeyKeyLengthNode.asString()).isEqualTo("2048");

        // Signature under PrivateKey
        INode privateKeySignatureNode = privateKeyNode.getChildren().get(Signature.class);
        assertThat(privateKeySignatureNode).isNotNull();
        assertThat(privateKeySignatureNode.asString()).isEqualTo("RSASSA-PSS");

        // MessageDigest under Signature under PrivateKey
        INode privateKeyMessageDigestNode =
                privateKeySignatureNode.getChildren().get(MessageDigest.class);
        assertThat(privateKeyMessageDigestNode).isNotNull();
        assertThat(privateKeyMessageDigestNode.asString()).isEqualTo("SHA384");

        // Sign under Signature under PrivateKey
        INode privateKeySignNode = privateKeySignatureNode.getChildren().get(Sign.class);
        assertThat(privateKeySignNode).isNotNull();
        assertThat(privateKeySignNode.asString()).isEqualTo("SIGN");

        // Algorithm under Signature under PrivateKey
        INode privateKeyAlgorithmNode = privateKeySignatureNode.getChildren().get(Algorithm.class);
        assertThat(privateKeyAlgorithmNode).isNotNull();
        assertThat(privateKeyAlgorithmNode.asString()).isEqualTo("RSA");

        // KeyLength under Algorithm under Signature under PrivateKey
        INode privateKeyAlgorithmKeyLengthNode =
                privateKeyAlgorithmNode.getChildren().get(KeyLength.class);
        assertThat(privateKeyAlgorithmKeyLengthNode).isNotNull();
        assertThat(privateKeyAlgorithmKeyLengthNode.asString()).isEqualTo("2048");

        // ProbabilisticSignatureScheme under Signature under PrivateKey
        INode pssNode =
                privateKeySignatureNode.getChildren().get(ProbabilisticSignatureScheme.class);
        assertThat(pssNode).isNotNull();
        assertThat(pssNode.asString()).isEqualTo("PSS");

        // MaskGenerationFunction under ProbabilisticSignatureScheme under Signature under
        // PrivateKey
        INode mgfNode = pssNode.getChildren().get(MaskGenerationFunction.class);
        assertThat(mgfNode).isNotNull();
        assertThat(mgfNode.asString()).isEqualTo("MGF1");

        // MessageDigest under MaskGenerationFunction under ProbabilisticSignatureScheme under
        // Signature under PrivateKey
        INode messageDigestNode = mgfNode.getChildren().get(MessageDigest.class);
        assertThat(messageDigestNode).isNotNull();
        assertThat(messageDigestNode.asString()).isEqualTo("SHA256");

        // Algorithm under PrivateKey
        INode privateKeyAlgorithmNode1 = privateKeyNode.getChildren().get(Algorithm.class);
        assertThat(privateKeyAlgorithmNode1).isNotNull();
        assertThat(privateKeyAlgorithmNode1.asString()).isEqualTo("RSA");

        // KeyLength under Algorithm under PrivateKey
        privateKeyAlgorithmKeyLengthNode =
                privateKeyAlgorithmNode1.getChildren().get(KeyLength.class);
        assertThat(privateKeyAlgorithmKeyLengthNode).isNotNull();
        assertThat(privateKeyAlgorithmKeyLengthNode.asString()).isEqualTo("2048");

        // KeyGeneration under Algorithm under PrivateKey
        INode privateKeyAlgorithmKeyGenerationNode =
                privateKeyAlgorithmNode1.getChildren().get(KeyGeneration.class);
        assertThat(privateKeyAlgorithmKeyGenerationNode).isNotNull();
        assertThat(privateKeyAlgorithmKeyGenerationNode.asString()).isEqualTo("KEYGENERATION");

        // PublicKey
        INode publicKeyNode = nodes.get(1);
        assertThat(publicKeyNode)
                .isInstanceOfAny(PublicKey.class, Key.class); // Special case because of .deepCopy
        assertThat(publicKeyNode.getChildren()).hasSize(2); // Two children detected

        // KeyLength under PublicKey
        INode publicKeyKeyLengthNode = publicKeyNode.getChildren().get(KeyLength.class);
        assertThat(publicKeyKeyLengthNode).isNotNull();
        assertThat(publicKeyKeyLengthNode.asString()).isEqualTo("2048");

        // Algorithm under PublicKey
        INode publicKeyAlgorithmNode = publicKeyNode.getChildren().get(Algorithm.class);
        assertThat(publicKeyAlgorithmNode).isNotNull();
        assertThat(publicKeyAlgorithmNode.asString()).isEqualTo("RSA");

        // KeyLength under Algorithm under PublicKey
        INode publicKeyAlgorithmKeyLengthNode =
                publicKeyAlgorithmNode.getChildren().get(KeyLength.class);
        assertThat(publicKeyAlgorithmKeyLengthNode).isNotNull();
        assertThat(publicKeyAlgorithmKeyLengthNode.asString()).isEqualTo("2048");

        // KeyGeneration under Algorithm under PublicKey
        INode publicKeyAlgorithmKeyGenerationNode =
                publicKeyAlgorithmNode.getChildren().get(KeyGeneration.class);
        assertThat(publicKeyAlgorithmKeyGenerationNode).isNotNull();
        assertThat(publicKeyAlgorithmKeyGenerationNode.asString()).isEqualTo("KEYGENERATION");
    }
}
