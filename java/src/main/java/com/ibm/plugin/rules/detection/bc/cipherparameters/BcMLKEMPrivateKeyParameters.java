/*
 * SonarQube Cryptography Plugin
 * Copyright (C) 2025 IBM
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
package com.ibm.plugin.rules.detection.bc.cipherparameters;

import com.ibm.engine.model.AlgorithmParameter;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.factory.AlgorithmParameterFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.tree.Tree;

@SuppressWarnings("java:S1192")
public final class BcMLKEMPrivateKeyParameters {

    private BcMLKEMPrivateKeyParameters() {
        // nothing
    }

    private static final IDetectionRule<Tree> MLKEM_PRIVATE_KEY_PARAMETERS_1 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters")
                    .forConstructor()
                    .withMethodParameter("org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters")
                    .shouldBeDetectedAs(
                            new AlgorithmParameterFactory<>(AlgorithmParameter.Kind.ANY))
                    .withMethodParameter("byte[]")
                    .buildForContext(new KeyContext())
                    .inBundle(() -> "Bc")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> MLKEM_PRIVATE_KEY_PARAMETERS_2 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters")
                    .forConstructor()
                    .withMethodParameter("org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters")
                    .shouldBeDetectedAs(
                            new AlgorithmParameterFactory<>(AlgorithmParameter.Kind.ANY))
                    .withMethodParameter("byte[]")
                    .withMethodParameter("byte[]")
                    .withMethodParameter("byte[]")
                    .withMethodParameter("byte[]")
                    .withMethodParameter("byte[]")
                    .buildForContext(new KeyContext())
                    .inBundle(() -> "Bc")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> MLKEM_PRIVATE_KEY_PARAMETERS_3 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters")
                    .forConstructor()
                    .withMethodParameter("org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters")
                    .shouldBeDetectedAs(
                            new AlgorithmParameterFactory<>(AlgorithmParameter.Kind.ANY))
                    .withMethodParameter("byte[]")
                    .withMethodParameter("byte[]")
                    .withMethodParameter("byte[]")
                    .withMethodParameter("byte[]")
                    .withMethodParameter("byte[]")
                    .withMethodParameter("byte[]")
                    .buildForContext(new KeyContext())
                    .inBundle(() -> "Bc")
                    .withoutDependingDetectionRules();

    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(
                MLKEM_PRIVATE_KEY_PARAMETERS_1,
                MLKEM_PRIVATE_KEY_PARAMETERS_2,
                MLKEM_PRIVATE_KEY_PARAMETERS_3);
    }
}
