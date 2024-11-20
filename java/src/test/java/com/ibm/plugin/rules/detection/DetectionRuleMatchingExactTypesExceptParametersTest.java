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
package com.ibm.plugin.rules.detection;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.detection.Finding;
import com.ibm.engine.model.IAction;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.engine.utils.DetectionStoreLogger;
import com.ibm.mapper.model.INode;
import com.ibm.plugin.TestBase;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.Test;
import org.sonar.check.Rule;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonar.plugins.java.api.JavaFileScannerContext;
import org.sonar.plugins.java.api.semantic.Symbol;
import org.sonar.plugins.java.api.tree.Tree;

@Rule(key = "Test")
class DetectionRuleMatchingExactTypesExceptParametersTest extends TestBase {

    public DetectionRuleMatchingExactTypesExceptParametersTest() {
        super(
                List.of(
                        new DetectionRuleBuilder<Tree>()
                                .createDetectionRule()
                                .forObjectTypes(
                                        "com.ibm.example.DetectionRuleMatchingExactTypesExceptParametersTestFile$Vehicle")
                                .forMethods("chooseShape")
                                .shouldBeDetectedAs(
                                        tree ->
                                                Optional.of(
                                                        new IAction<>() {
                                                            @Nonnull
                                                            @Override
                                                            public Tree getLocation() {
                                                                return tree;
                                                            }

                                                            @Nonnull
                                                            @Override
                                                            public String asString() {
                                                                return "chooseShape";
                                                            }
                                                        }))
                                .withMethodParameterMatchExactType(
                                        "com.ibm.example.DetectionRuleMatchingExactTypesExceptParametersTestFile$Shape")
                                .buildForContext(
                                        new IDetectionContext() {
                                            @Nonnull
                                            @Override
                                            public Class<? extends IDetectionContext> type() {
                                                return IDetectionContext.class;
                                            }
                                        })
                                .inBundle(() -> "testBundle")
                                .withoutDependingDetectionRules()));
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore,
            @Nonnull List<INode> nodes) {
        // nothing
    }

    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile(
                        "src/test/files/rules/detection/DetectionRuleMatchingExactTypesExceptParametersTestFile.java")
                .withChecks(this)
                .verifyIssues();
    }

    @Override
    public void update(@Nonnull Finding<JavaCheck, Tree, Symbol, JavaFileScannerContext> finding) {
        final DetectionStore<JavaCheck, Tree, Symbol, JavaFileScannerContext> detectionStore =
                finding.detectionStore();
        (new DetectionStoreLogger<JavaCheck, Tree, Symbol, JavaFileScannerContext>())
                .print(detectionStore);
        detectionStore
                .getDetectionValues()
                .forEach(
                        iValue -> {
                            this.reportIssue(iValue.getLocation(), iValue.asString());
                        });
    }
}
