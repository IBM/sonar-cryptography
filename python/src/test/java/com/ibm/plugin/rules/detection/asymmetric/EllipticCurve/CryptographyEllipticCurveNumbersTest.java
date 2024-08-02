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
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.context.PrivateKeyContext;
import com.ibm.engine.model.context.PublicKeyContext;
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Key;
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

public class CryptographyEllipticCurveNumbersTest extends TestBase {
    @Disabled // TODO: Make the curve lookout in the dictionnary work
    @Test
    void test() {
        PythonCheckVerifier.verify(
                "src/test/files/rules/detection/asymmetric/EllipticCurve/CryptographyEllipticCurveNumbersTestFile.py",
                this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> detectionStore,
            @Nonnull List<INode> nodes) {
        String curve = "SECP256R1";
        /*
         * Detection Store
         */
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        IValue<Tree> value = detectionStore.getDetectionValues().get(0);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(PublicKeyContext.class);
        assertThat(value).isInstanceOf(Algorithm.class);
        assertThat(value.asString()).isEqualTo(curve);

        DetectionStore<PythonCheck, Tree, Symbol, PythonVisitorContext> store =
                getStoreOfValueType(KeyAction.class, detectionStore.getChildren());
        assertThat(store).isNotNull();
        assertThat(store.getDetectionValueContext()).isInstanceOf(PrivateKeyContext.class);
        assertThat(store.getDetectionValues()).hasSize(1);
        value = store.getDetectionValues().get(0);
        assertThat(value).isInstanceOf(KeyAction.class);
        assertThat(value.asString()).isEqualTo("GENERATION");

        /*
         * Translation
         */
        assertThat(nodes).hasSize(2);

        // Assert PublicKey translation
        INode publicKeyNode = nodes.get(0);
        assertThat(publicKeyNode).isInstanceOf(PublicKey.class);
        assertThat(publicKeyNode.asString()).isEqualTo("EC");

        INode ellipticCurveAlgorithmNode =
                publicKeyNode.getChildren().get(EllipticCurveAlgorithm.class);
        assertThat(ellipticCurveAlgorithmNode).isNotNull();
        assertThat(ellipticCurveAlgorithmNode.asString()).isEqualTo("EC");

        INode ellipticCurveNode = ellipticCurveAlgorithmNode.getChildren().get(EllipticCurve.class);
        assertThat(ellipticCurveNode).isNotNull();
        assertThat(ellipticCurveNode.asString()).isEqualTo(curve);

        INode publicKeyGenerationNode =
                ellipticCurveAlgorithmNode.getChildren().get(KeyGeneration.class);
        assertThat(publicKeyGenerationNode).isNotNull();
        assertThat(publicKeyGenerationNode.asString()).isEqualTo("KEYGENERATION");

        // Assert PrivateKey translation
        INode privateKeyNode = nodes.get(1);
        assertThat(publicKeyNode).isInstanceOfAny(PrivateKey.class, Key.class);
        assertThat(privateKeyNode.asString()).isEqualTo("EC");

        INode privateKeyEllipticCurveAlgorithmNode =
                privateKeyNode.getChildren().get(EllipticCurveAlgorithm.class);
        assertThat(privateKeyEllipticCurveAlgorithmNode).isNotNull();
        assertThat(privateKeyEllipticCurveAlgorithmNode.asString()).isEqualTo("EC");

        INode privateKeyEllipticCurveNode =
                privateKeyEllipticCurveAlgorithmNode.getChildren().get(EllipticCurve.class);
        assertThat(privateKeyEllipticCurveNode).isNotNull();
        assertThat(privateKeyEllipticCurveNode.asString()).isEqualTo(curve);

        INode privateKeyGenerationNode =
                privateKeyEllipticCurveAlgorithmNode.getChildren().get(KeyGeneration.class);
        assertThat(privateKeyGenerationNode).isNotNull();
        assertThat(privateKeyGenerationNode.asString()).isEqualTo("KEYGENERATION");
    }
}
