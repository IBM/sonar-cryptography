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

import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.JavaInventoryRule;
import java.util.List;
import java.util.Optional;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;
import org.sonar.check.Rule;
import org.sonar.java.checks.verifier.CheckVerifier;
import org.sonar.plugins.java.api.tree.Tree;

@Rule(key = "Test")
class DetectionRuleMatchingExactTypesTest extends JavaInventoryRule {

    public DetectionRuleMatchingExactTypesTest() {
        super(
                List.of(
                        new DetectionRuleBuilder<Tree>()
                                .createDetectionRule()
                                .forObjectExactTypes("java.lang.Object")
                                .forMethods("equals")
                                .withMethodParameterMatchExactType("java.lang.String")
                                .shouldBeDetectedAs(
                                        objectTreeResolvedValue -> {
                                            final IValue<Tree> testValue =
                                                    new IValue<>() {
                                                        @NotNull @Override
                                                        public Tree getLocation() {
                                                            return objectTreeResolvedValue.tree();
                                                        }

                                                        @NotNull @Override
                                                        public String asString() {
                                                            return "value";
                                                        }
                                                    };
                                            return Optional.of(testValue);
                                        })
                                .buildForContext(
                                        new IDetectionContext() {
                                            @NotNull @Override
                                            public Class<? extends IDetectionContext> type() {
                                                return IDetectionContext.class;
                                            }
                                        })
                                .inBundle(() -> "testBundle")
                                .withoutDependingDetectionRules()));
    }

    @Test
    void test() {
        CheckVerifier.newVerifier()
                .onFile(
                        "src/test/files/rules/detection/DetectionRuleMatchingExactTypesTestFile.java")
                .withChecks(this)
                .verifyIssues();
    }
}
