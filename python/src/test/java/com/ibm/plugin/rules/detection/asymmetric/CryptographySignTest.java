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
package com.ibm.plugin.rules.detection.asymmetric;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.context.PrivateKeyContext;
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.EllipticCurveAlgorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Key;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.PrivateKey;
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

class CryptographySignTest extends TestBase {
    @Test
    void test() {
        PythonCheckVerifier.verify(
                "src/test/files/rules/detection/asymmetric/CryptographySignTestFile.py", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> detectionStore,
            @Nonnull List<INode> nodes) {
        String curve = findingId > 0 ? "Curve448" : "Curve25519";
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

        // Signature under PrivateKey
        INode signatureNode = privateKeyNode.getChildren().get(Signature.class);
        assertThat(signatureNode).isNotNull();
        assertThat(signatureNode.asString()).isEqualTo("EdDSA");

        // MessageDigest under Signature
        INode messageDigestNode = signatureNode.getChildren().get(MessageDigest.class);
        assertThat(messageDigestNode).isNotNull();
        assertThat(messageDigestNode.asString()).isEqualTo("SHA-512");

        // EllipticCurveAlgorithm under Signature
        INode signNode = signatureNode.getChildren().get(Sign.class);
        assertThat(signNode).isNotNull();
        assertThat(signNode.asString()).isEqualTo("SIGN");

        // Sign under Signature
        INode curveAlgorithmNode = signatureNode.getChildren().get(EllipticCurveAlgorithm.class);
        assertThat(curveAlgorithmNode).isNotNull();
        assertThat(curveAlgorithmNode.asString()).isEqualTo("EC");

        // EllipticCurve under EllipticCurveAlgorithm under Signature
        INode curveNode = curveAlgorithmNode.getChildren().get(EllipticCurve.class);
        assertThat(curveNode).isNotNull();
        assertThat(curveNode.asString()).isEqualTo(curve);

        // EllipticCurveAlgorithm under PrivateKey
        INode privateKeyAlgorithmNode =
                privateKeyNode.getChildren().get(EllipticCurveAlgorithm.class);
        assertThat(privateKeyAlgorithmNode).isNotNull();
        assertThat(privateKeyAlgorithmNode.asString()).isEqualTo("EC");

        // KeyGeneration under EllipticCurveAlgorithm under PrivateKey
        INode privateKeyKeyGenerationNode =
                privateKeyAlgorithmNode.getChildren().get(KeyGeneration.class);
        assertThat(privateKeyKeyGenerationNode).isNotNull();
        assertThat(privateKeyKeyGenerationNode.asString()).isEqualTo("KEYGENERATION");

        // EllipticCurve under EllipticCurveAlgorithm under PrivateKey
        INode privateKeyCurveNode = privateKeyAlgorithmNode.getChildren().get(EllipticCurve.class);
        assertThat(privateKeyCurveNode).isNotNull();
        assertThat(privateKeyCurveNode.asString()).isEqualTo(curve);

        // PublicKey
        INode publicKeyNode = nodes.get(1);
        assertThat(publicKeyNode).isInstanceOfAny(PublicKey.class, Key.class);
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
        assertThat(publicKeyCurveNode.asString()).isEqualTo(curve);
    }
}
