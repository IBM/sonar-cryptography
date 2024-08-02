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
package com.ibm.plugin.rules.detection.asymmetric.EllipticCurve;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.CipherAction;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.SignatureAction;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.PrivateKeyContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Key;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.PrivateKey;
import com.ibm.mapper.model.PublicKey;
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

public class CryptographyEllipticCurveSignTest extends TestBase {
    @Test
    void test() {
        PythonCheckVerifier.verify(
                "src/test/files/rules/detection/asymmetric/EllipticCurve/CryptographyEllipticCurveSignTestFile.py",
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
        assertThat(value).isInstanceOf(Algorithm.class);
        assertThat(value.asString()).isEqualTo("SECP384R1");

        DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> store =
                getStoreOfValueType(Algorithm.class, detectionStore.getChildren());
        assertThat(store).isNotNull();
        assertThat(store.getDetectionValueContext()).isInstanceOf(SignatureContext.class);
        assertThat(store.getDetectionValues()).hasSize(2);
        value = store.getDetectionValues().get(0);
        assertThat(value).isInstanceOf(SignatureAction.class);
        assertThat(value.asString()).isEqualTo("SIGN");
        value = store.getDetectionValues().get(1);
        assertThat(value).isInstanceOf(Algorithm.class);
        assertThat(value.asString()).isEqualTo("ECDSA");

        store = getStoreOfValueType(CipherAction.class, store.getChildren());
        assertThat(store).isNotNull();
        assertThat(store.getDetectionValueContext()).isInstanceOf(DigestContext.class);
        assertThat(store.getDetectionValues()).hasSize(1);
        value = store.getDetectionValues().get(0);
        assertThat(value).isInstanceOf(CipherAction.class);
        assertThat(value.asString()).isEqualTo("HASH");

        /*
         * Translation
         */
        assertThat(nodes).hasSize(2);

        // PrivateKey
        INode privateKeyNode = nodes.get(0);
        assertThat(privateKeyNode).isInstanceOf(PrivateKey.class);
        assertThat(privateKeyNode.getChildren()).hasSize(2);

        // Signature under PrivateKey
        INode privateKeySignatureNode = privateKeyNode.getChildren().get(Signature.class);
        assertThat(privateKeySignatureNode).isNotNull();
        assertThat(privateKeySignatureNode.asString()).isEqualTo("ECDSA");

        // MessageDigest under Signature under PrivateKey
        INode privateKeyMessageDigestNode =
                privateKeySignatureNode.getChildren().get(MessageDigest.class);
        assertThat(privateKeyMessageDigestNode).isNotNull();
        assertThat(privateKeyMessageDigestNode.asString()).isEqualTo("SHA3-512");

        // Sign under Signature under PrivateKey
        INode signNode = privateKeySignatureNode.getChildren().get(Sign.class);
        assertThat(signNode).isNotNull();
        assertThat(signNode.asString()).isEqualTo("SIGN");

        // EllipticCurveAlgorithm under Signature under PrivateKey
        INode privateKeyAlgorithmNode =
                privateKeySignatureNode.getChildren().get(EllipticCurveAlgorithm.class);
        assertThat(privateKeyAlgorithmNode).isNotNull();
        assertThat(privateKeyAlgorithmNode.asString()).isEqualTo("EC");

        // EllipticCurve under EllipticCurveAlgorithm under Signature under PrivateKey
        INode privateKeyCurveNode = privateKeyAlgorithmNode.getChildren().get(EllipticCurve.class);
        assertThat(privateKeyCurveNode).isNotNull();
        assertThat(privateKeyCurveNode.asString()).isEqualTo("SECP384R1");

        // PublicKey
        INode publicKeyNode = nodes.get(1);
        assertThat(publicKeyNode)
                .isInstanceOfAny(PublicKey.class, Key.class); // Special case because of .deepCopy
        assertThat(publicKeyNode.getChildren()).hasSize(1);

        // EllipticCurveAlgorithm under PublicKey
        INode publicKeyAlgorithmNode =
                publicKeyNode.getChildren().get(EllipticCurveAlgorithm.class);
        assertThat(publicKeyAlgorithmNode).isNotNull();
        assertThat(publicKeyAlgorithmNode.asString()).isEqualTo("EC");

        // KeyGeneration under EllipticCurveAlgorithm under PublicKey
        INode publicKeyKeyGenerationNode =
                publicKeyAlgorithmNode.getChildren().get(KeyGeneration.class);
        assertThat(publicKeyKeyGenerationNode).isNotNull();
        assertThat(publicKeyKeyGenerationNode.asString()).isEqualTo("KEYGENERATION");

        // EllipticCurve under EllipticCurveAlgorithm under PublicKey
        INode publicKeyCurveNode = publicKeyAlgorithmNode.getChildren().get(EllipticCurve.class);
        assertThat(publicKeyCurveNode).isNotNull();
        assertThat(publicKeyCurveNode.asString()).isEqualTo("SECP384R1");
    }
}
