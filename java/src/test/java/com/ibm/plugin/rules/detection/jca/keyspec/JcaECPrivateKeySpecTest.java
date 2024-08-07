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
package com.ibm.plugin.rules.detection.jca.keyspec;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.mapper.model.EllipticCurve;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Key;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.Unknown;
import com.ibm.mapper.model.functionality.KeyGeneration;
import com.ibm.plugin.TestBase;
import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

import javax.annotation.Nonnull;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class JcaECPrivateKeySpecTest extends TestBase {

    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile(
                        "src/test/files/rules/detection/jca/keyspec/JcaECPrivateKeySpecTestFile.java")
                .withChecks(this)
                .verifyIssues();
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes) {
        /*
         * Detection Store
         */

        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(KeyContext.class);
        IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
        assertThat(value0).isInstanceOf(Algorithm.class);
        assertThat(value0.asString()).isEqualTo("EC");


        /*
         * Translation
         */

        assertThat(nodes).hasSize(1);

// Key
        INode keyNode = nodes.get(0);
        assertThat(keyNode.getKind()).isEqualTo(Key.class);
        assertThat(keyNode.getChildren()).hasSize(2);
        assertThat(keyNode.asString()).isEqualTo("EC");

// Unknown under Key
        INode unknownNode = keyNode.getChildren().get(Unknown.class);
        assertThat(unknownNode).isNotNull();
        assertThat(unknownNode.getChildren()).hasSize(2);
        assertThat(unknownNode.asString()).isEqualTo("EC");

// KeyGeneration under Unknown under Key
        INode keyGenerationNode = unknownNode.getChildren().get(KeyGeneration.class);
        assertThat(keyGenerationNode).isNotNull();
        assertThat(keyGenerationNode.getChildren()).isEmpty();
        assertThat(keyGenerationNode.asString()).isEqualTo("KEYGENERATION");

// Unknown under Unknown under Key
        INode unknownNode1 = unknownNode.getChildren().get(Unknown.class);
        assertThat(unknownNode1).isNotNull();
        assertThat(unknownNode1.getChildren()).isEmpty();
        assertThat(unknownNode1.asString()).isEqualTo("Unknown");

// Key under Key
        INode keyNode1 = keyNode.getChildren().get(Key.class);
        assertThat(keyNode1).isNotNull();
        assertThat(keyNode1.getChildren()).hasSize(1);
        assertThat(keyNode1.asString()).isEqualTo("EC-secp256r1");

// PublicKeyEncryption under Key under Key
        INode publicKeyEncryptionNode = keyNode1.getChildren().get(PublicKeyEncryption.class);
        assertThat(publicKeyEncryptionNode).isNotNull();
        assertThat(publicKeyEncryptionNode.getChildren()).hasSize(1);
        assertThat(publicKeyEncryptionNode.asString()).isEqualTo("EC-secp256r1");

// EllipticCurve under PublicKeyEncryption under Key under Key
        INode ellipticCurveNode = publicKeyEncryptionNode.getChildren().get(EllipticCurve.class);
        assertThat(ellipticCurveNode).isNotNull();
        assertThat(ellipticCurveNode.getChildren()).isEmpty();
        assertThat(ellipticCurveNode.asString()).isEqualTo("secp256r1");


    }
}
