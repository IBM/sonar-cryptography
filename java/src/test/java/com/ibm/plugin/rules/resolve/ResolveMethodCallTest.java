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
package com.ibm.plugin.rules.resolve;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.model.Algorithm;
import com.ibm.engine.model.Curve;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.TestBase;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

class ResolveMethodCallTest extends TestBase {

    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile("src/test/files/rules/resolve/ResolveMethodCallTestFile.java")
                .withChecks(this)
                .verifyIssues();
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes) {
        assertThat(detectionStore.getDetectionValues()).hasSize(1);
        IValue<Tree> value = detectionStore.getDetectionValues().get(0);
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(KeyContext.class);
        assertThat(value).isInstanceOf(Algorithm.class);
        assertThat(value.asString()).isEqualTo("EC");

        List<DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext>> curves =
                getStoresOfValueType(Curve.class, detectionStore.getChildren());
        assertThat(curves).hasSize(3);

        AtomicBoolean saw_secp256r1 = new AtomicBoolean(false);
        AtomicBoolean saw_secp384r1 = new AtomicBoolean(false);
        AtomicBoolean saw_secp521r1 = new AtomicBoolean(false);
        for (DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> curve : curves) {
            assertThat(curve.getDetectionValues()).hasSize(1);
            IValue<Tree> curveValue = curve.getDetectionValues().get(0);
            assertThat(curve.getDetectionValueContext()).isInstanceOf(KeyContext.class);
            KeyContext context = (KeyContext) curve.getDetectionValueContext();
            assertThat(context.kind()).isEqualTo(KeyContext.Kind.EC);
            assertThat(curveValue).isInstanceOf(Curve.class);
            assertThat(curveValue.asString())
                    .satisfies(
                            str -> {
                                switch (str) {
                                    case "secp256r1" -> {
                                        assertThat(saw_secp256r1.get()).isFalse();
                                        saw_secp256r1.set(true);
                                    }
                                    case "secp384r1" -> {
                                        assertThat(saw_secp384r1.get()).isFalse();
                                        saw_secp384r1.set(true);
                                    }
                                    case "secp521r1" -> {
                                        assertThat(saw_secp521r1.get()).isFalse();
                                        saw_secp521r1.set(true);
                                    }
                                }
                            });
        }
    }
}
