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
package com.ibm.plugin.rules.detection.bc.encapsulatedsecret;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyDerivationFunction;
import com.ibm.mapper.model.KeyEncapsulationMechanism;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.functionality.Encapsulate;
import com.ibm.plugin.TestBase;
import com.ibm.plugin.rules.detection.bc.BouncyCastleJars;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

class BcECIESKEMGeneratorTest extends TestBase {
    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile(
                        "src/test/files/rules/detection/bc/encapsulatedsecret/BcECIESKEMGeneratorTestFile.java")
                .withChecks(this)
                .withClassPath(BouncyCastleJars.JARS)
                .verifyIssues();
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes) {
        /**
         * Optimally, we shouldn't have these direct detections of engines, as they appear in the
         * depending detection rules
         */
        if (findingId == 0) {
            return;
        }

        /*
         * Detection Store
         */

        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(KeyContext.class);
        IValue<Tree> value0 = detectionStore.getDetectionValues().get(0);
        assertThat(value0).isInstanceOf(ValueAction.class);
        assertThat(value0.asString()).isEqualTo("ECIESKEMGenerator");

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_1 =
                getStoreOfValueType(KeySize.class, detectionStore.getChildren());
        assertThat(store_1.getDetectionValues()).hasSize(1);
        assertThat(store_1.getDetectionValueContext()).isInstanceOf(KeyContext.class);
        IValue<Tree> value0_1 = store_1.getDetectionValues().get(0);
        assertThat(value0_1).isInstanceOf(KeySize.class);
        assertThat(value0_1.asString()).isEqualTo("2048");

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_2 =
                getStoreOfValueType(ValueAction.class, detectionStore.getChildren());
        assertThat(store_2.getDetectionValues()).hasSize(1);
        assertThat(store_2.getDetectionValueContext()).isInstanceOf(KeyContext.class);
        IValue<Tree> value0_2 = store_2.getDetectionValues().get(0);
        assertThat(value0_2).isInstanceOf(ValueAction.class);
        assertThat(value0_2.asString()).isEqualTo("HKDFBytesGenerator");

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> store_2_1 =
                getStoreOfValueType(ValueAction.class, store_2.getChildren());
        assertThat(store_2_1.getDetectionValues()).hasSize(1);
        assertThat(store_2_1.getDetectionValueContext()).isInstanceOf(DigestContext.class);
        IValue<Tree> value0_2_1 = store_2_1.getDetectionValues().get(0);
        assertThat(value0_2_1).isInstanceOf(ValueAction.class);
        assertThat(value0_2_1.asString()).isEqualTo("SHA256Digest");

        /*
         * Translation
         */

        assertThat(nodes).hasSize(1);

        // KeyEncapsulationMechanism
        INode keyEncapsulationMechanismNode = nodes.get(0);
        assertThat(keyEncapsulationMechanismNode.getKind())
                .isEqualTo(KeyEncapsulationMechanism.class);
        assertThat(keyEncapsulationMechanismNode.getChildren()).hasSize(3);
        assertThat(keyEncapsulationMechanismNode.asString()).isEqualTo("ECIES-KEM");

        // KeyLength under KeyEncapsulationMechanism
        INode keyLengthNode = keyEncapsulationMechanismNode.getChildren().get(KeyLength.class);
        assertThat(keyLengthNode).isNotNull();
        assertThat(keyLengthNode.getChildren()).isEmpty();
        assertThat(keyLengthNode.asString()).isEqualTo("2048");

        // KeyDerivationFunction under KeyEncapsulationMechanism
        INode keyDerivationFunctionNode1 =
                keyEncapsulationMechanismNode.getChildren().get(KeyDerivationFunction.class);
        assertThat(keyDerivationFunctionNode1).isNotNull();
        assertThat(keyDerivationFunctionNode1.getChildren()).hasSize(1);
        assertThat(keyDerivationFunctionNode1.asString()).isEqualTo("HKDF-SHA256");

        // MessageDigest under KeyDerivationFunction under KeyEncapsulationMechanism
        INode messageDigestNode1 =
                keyDerivationFunctionNode1.getChildren().get(MessageDigest.class);
        assertThat(messageDigestNode1).isNotNull();
        assertThat(messageDigestNode1.getChildren()).hasSize(4);
        assertThat(messageDigestNode1.asString()).isEqualTo("SHA256");

        // Decapsulate under KeyEncapsulationMechanism
        INode decapsulateNode = keyEncapsulationMechanismNode.getChildren().get(Encapsulate.class);
        assertThat(decapsulateNode).isNotNull();
        assertThat(decapsulateNode.getChildren()).isEmpty();
        assertThat(decapsulateNode.asString()).isEqualTo("ENCAPSULATE");
    }
}
