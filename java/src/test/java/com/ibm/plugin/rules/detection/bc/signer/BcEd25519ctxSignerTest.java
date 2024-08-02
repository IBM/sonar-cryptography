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
package com.ibm.plugin.rules.detection.bc.signer;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.OperationMode;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.mapper.model.ECAlgorithm;
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.functionality.Sign;
import com.ibm.plugin.TestBase;
import com.ibm.plugin.rules.detection.bc.BouncyCastleJars;
import java.util.List;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

class BcEd25519ctxSignerTest extends TestBase {
    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile("src/test/files/rules/detection/bc/signer/BcEd25519ctxSignerTestFile.java")
                .withChecks(this)
                .withClassPath(BouncyCastleJars.JARS)
                .verifyIssues();
    }

    @Override
    public void asserts(
            int findingId,
            @NotNull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @NotNull List<INode> nodes) {
        /*
         * Detection Store
         */

        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(SignatureContext.class);
        IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
        assertThat(value0).isInstanceOf(ValueAction.class);
        assertThat(value0.asString()).isEqualTo("Ed25519");

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_1 =
                getStoreOfValueType(OperationMode.class, detectionStore.getChildren());
        assertThat(store_1.getDetectionValues()).hasSize(1);
        assertThat(store_1.getDetectionValueContext()).isInstanceOf(SignatureContext.class);
        IValue<Tree> value0_1 = store_1.getDetectionValues().get(0);
        assertThat(value0_1).isInstanceOf(OperationMode.class);
        assertThat(value0_1.asString()).isEqualTo("1");

        /*
         * Translation
         */

        assertThat(nodes).hasSize(1);

        // Signature
        INode signatureNode = nodes.get(0);
        assertThat(signatureNode.getKind()).isEqualTo(Signature.class);
        assertThat(signatureNode.getChildren()).hasSize(2);
        assertThat(signatureNode.asString()).isEqualTo("EdDSA");

        // EllipticCurveAlgorithm under Signature
        INode ellipticCurveAlgorithmNode = signatureNode.getChildren().get(ECAlgorithm.class);
        assertThat(ellipticCurveAlgorithmNode).isNotNull();
        assertThat(ellipticCurveAlgorithmNode.getChildren()).hasSize(1);
        assertThat(ellipticCurveAlgorithmNode.asString()).isEqualTo("EC");

        // EllipticCurve under EllipticCurveAlgorithm under Signature
        INode ellipticCurveNode = ellipticCurveAlgorithmNode.getChildren().get(EllipticCurve.class);
        assertThat(ellipticCurveNode).isNotNull();
        assertThat(ellipticCurveNode.getChildren()).isEmpty();
        assertThat(ellipticCurveNode.asString()).isEqualTo("Curve25519");

        // Sign under Signature
        INode signNode = signatureNode.getChildren().get(Sign.class);
        assertThat(signNode).isNotNull();
        assertThat(signNode.getChildren()).isEmpty();
        assertThat(signNode.asString()).isEqualTo("SIGN");
    }
}
