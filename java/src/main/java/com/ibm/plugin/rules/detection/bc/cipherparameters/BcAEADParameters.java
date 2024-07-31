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
package com.ibm.plugin.rules.detection.bc.cipherparameters;

import static com.ibm.plugin.rules.detection.TypeShortcuts.BYTE_ARRAY_TYPE;

import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.AlgorithmParameterContext;
import com.ibm.engine.model.factory.MacSizeFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import javax.annotation.Nonnull;
import org.jetbrains.annotations.Unmodifiable;
import org.sonar.plugins.java.api.tree.Tree;

public final class BcAEADParameters {

    private BcAEADParameters() {
        // nothing
    }

    private static final IDetectionRule<Tree> CONSTRUCTOR_1 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    // Using "exact types" because AEADParameters is the parent of CCMParameters
                    .forObjectExactTypes("org.bouncycastle.crypto.params.AEADParameters")
                    .forConstructor()
                    .withMethodParameter("org.bouncycastle.crypto.params.KeyParameter")
                    .addDependingDetectionRules(BcKeyParameter.rules())
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(new MacSizeFactory<>(Size.UnitType.BIT))
                    .withMethodParameter(BYTE_ARRAY_TYPE)
                    .buildForContext(
                            new AlgorithmParameterContext(AlgorithmParameterContext.Kind.AEAD))
                    .inBundle(() -> "Bc")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> CONSTRUCTOR_2 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    // Using "exact types" because AEADParameters is the parent of CCMParameters
                    .forObjectExactTypes("org.bouncycastle.crypto.params.AEADParameters")
                    .forConstructor()
                    .withMethodParameter("org.bouncycastle.crypto.params.KeyParameter")
                    .addDependingDetectionRules(BcKeyParameter.rules())
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(new MacSizeFactory<>(Size.UnitType.BIT))
                    .withMethodParameter(BYTE_ARRAY_TYPE)
                    .withMethodParameter(BYTE_ARRAY_TYPE)
                    .buildForContext(
                            new AlgorithmParameterContext(AlgorithmParameterContext.Kind.AEAD))
                    .inBundle(() -> "Bc")
                    .withoutDependingDetectionRules();

    @Unmodifiable
    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(CONSTRUCTOR_1, CONSTRUCTOR_2);
    }
}
