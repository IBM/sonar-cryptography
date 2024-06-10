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
package com.ibm.plugin.rules.detection.jca.signature;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.SaltSize;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.mapper.model.*;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

class JcaSignatureSetParameter3Test extends TestBase {

    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile(
                        "src/test/files/rules/detection/jca/signature/JcaSignatureSetParameter3TestFile.java")
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
        IValue<Tree> value = detectionStore.getDetectionValues().get(0);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(SignatureContext.class);
        assertThat(value).isInstanceOf(Algorithm.class);
        assertThat(value.asString()).isEqualTo("RSASSA-PSS");

        DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> pssStore =
                getStoreOfValueType(Algorithm.class, detectionStore.getChildren());
        assertThat(pssStore).isNotNull();
        assertThat(pssStore.getDetectionValueContext()).isInstanceOf(SignatureContext.class);
        assertThat(pssStore.getDetectionValues()).hasSize(3);
        for (IValue<Tree> v : pssStore.getDetectionValues()) {
            assertThat(v).isOfAnyClassIn(Algorithm.class, SaltSize.class);
            assertThat(v.asString()).containsAnyOf("SHA3-256", "MGF1", "160");
            if (v.asString().equals("MGF1")) {
                assertThat(pssStore.getChildrenForParameterWithId(1)).isPresent();
                DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> mgf1md =
                        getStoreOfValueType(
                                Algorithm.class, pssStore.getChildrenForParameterWithId(1).get());
                assertThat(mgf1md).isNotNull();
                assertThat(mgf1md.getDetectionValues()).hasSize(1);
                IValue<Tree> md = mgf1md.getDetectionValues().get(0);
                assertThat(mgf1md.getDetectionValueContext()).isInstanceOf(SignatureContext.class);
                assertThat(md).isInstanceOf(Algorithm.class);
                assertThat(md.asString()).isEqualTo("SHA1");
            }
        }

        /*
         * Translation
         */
        assertThat(nodes).hasSize(1);
        INode node = nodes.get(0);
        assertThat(node).isInstanceOf(Signature.class);
        assertThat(node.asString()).isEqualTo("RSASSA-PSS");

        INode algorithm = node.getChildren().get(com.ibm.mapper.model.Algorithm.class);
        assertThat(algorithm).isNotNull();
        assertThat(algorithm.asString()).isEqualTo("RSA");
        INode oid = algorithm.getChildren().get(Oid.class);
        assertThat(oid).isNotNull();
        assertThat(oid.asString()).isEqualTo("1.2.840.113549.1.1.1");
        INode keyLength = algorithm.getChildren().get(KeyLength.class);
        assertThat(keyLength).isNotNull();
        assertThat(keyLength.asString()).isEqualTo("2048");

        oid = node.getChildren().get(Oid.class);
        assertThat(oid).isNotNull();
        assertThat(oid.asString()).isEqualTo("2.16.840.1.101.3.4.3.14");

        INode mgf1 = node.getChildren().get(MaskGenerationFunction.class);
        assertThat(mgf1).isNotNull();
        assertThat(mgf1.asString()).isEqualTo("MGF1");
        INode md = mgf1.getChildren().get(MessageDigest.class);
        assertThat(md).isNotNull();
        assertThat(md.asString()).isEqualTo("SHA-1");

        INode pss = node.getChildren().get(ProbabilisticSignatureScheme.class);
        assertThat(pss).isNotNull();
        assertThat(pss.asString()).isEqualTo("PSS");

        INode salt = node.getChildren().get(SaltLength.class);
        assertThat(salt).isNotNull();
        assertThat(salt.asString()).isEqualTo("160");

        md = node.getChildren().get(MessageDigest.class);
        assertThat(md).isNotNull();
        assertThat(md.asString()).isEqualTo("SHA3-256");
    }
}
