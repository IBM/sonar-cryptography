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
package com.ibm.plugin.rules.detection.jca.keyagreement;

import static com.ibm.plugin.rules.detection.TypeShortcuts.STRING_TYPE;

import com.ibm.engine.model.context.KeyAgreementContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import java.util.stream.Stream;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

@SuppressWarnings("java:S1192")
public final class JcaKeyAgreementGetInstance {
    private static final IDetectionRule<Tree> KEY_AGREEMENT1 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("javax.crypto.KeyAgreement")
                    .forMethods("getInstance")
                    .withMethodParameter(STRING_TYPE)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> "Jca")
                    .withDependingDetectionRules(
                            Stream.concat(
                                            JcaKeyAgreementInit.rules().stream(),
                                            JcaKeyAgreementGenerateSecret.rules().stream())
                                    .toList());

    private static final IDetectionRule<Tree> KEY_AGREEMENT2 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("javax.crypto.KeyAgreement")
                    .forMethods("getInstance")
                    .withMethodParameter(STRING_TYPE)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter("java.security.Provider")
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> "Jca")
                    .withDependingDetectionRules(
                            Stream.concat(
                                            JcaKeyAgreementInit.rules().stream(),
                                            JcaKeyAgreementGenerateSecret.rules().stream())
                                    .toList());

    private static final IDetectionRule<Tree> KEY_AGREEMENT3 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("javax.crypto.KeyAgreement")
                    .forMethods("getInstance")
                    .withMethodParameter(STRING_TYPE)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter(STRING_TYPE)
                    .buildForContext(new KeyAgreementContext())
                    .inBundle(() -> "Jca")
                    .withDependingDetectionRules(
                            Stream.concat(
                                            JcaKeyAgreementInit.rules().stream(),
                                            JcaKeyAgreementGenerateSecret.rules().stream())
                                    .toList());

    private JcaKeyAgreementGetInstance() {
        // nothing
    }

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(KEY_AGREEMENT1, KEY_AGREEMENT2, KEY_AGREEMENT3);
    }
}
