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
package com.ibm.plugin.rules.detection.asymmetric;

import static com.ibm.engine.detection.MethodMatcher.ANY;

import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.PrivateKeyContext;
import com.ibm.engine.model.context.PublicKeyContext;
import com.ibm.engine.model.factory.KeyActionFactory;
import com.ibm.engine.model.factory.KeySizeFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import javax.annotation.Nonnull;
import org.jetbrains.annotations.Unmodifiable;
import org.sonar.plugins.python.api.tree.Tree;

@SuppressWarnings("java:S1192")
public final class CryptographyDiffieHellman {

    private CryptographyDiffieHellman() {
        // private
    }

    private static final String TYPE = "cryptography.hazmat.primitives.asymmetric.dh";

    // TODO: The key size does not yet appear in CryptographyDiffieHellmanGenerateTestFile because
    //  of the TraceSymbol problem documented on the Github issue
    private static final IDetectionRule<Tree> GENERATE_PARAMETERS_DH =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(TYPE)
                    .forMethods("generate_parameters")
                    .withMethodParameter(ANY)
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                    .buildForContext(new PrivateKeyContext(KeyContext.Kind.DH))
                    .inBundle(() -> "CryptographyDiffieHellmanGenerationParam")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> GENERATION_DH =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(TYPE + ".generate_parameters")
                    .forMethods("generate_private_key")
                    .shouldBeDetectedAs(new KeyActionFactory<>(KeyAction.Action.GENERATION))
                    .withAnyParameters()
                    // The DH_FULL context indicates that the finding comes from
                    // `generate_private_key` that creates both Private and Public keys
                    // It distinguishes this case from the DH context used in Public/PrivateNumbers,
                    // where only the Public or Private key is created
                    .buildForContext(new PrivateKeyContext(KeyContext.Kind.DH_FULL))
                    .inBundle(() -> "CryptographyDiffieHellman")
                    .withDependingDetectionRules(List.of(GENERATE_PARAMETERS_DH));

    private static final IDetectionRule<Tree> PUBLIC_NUMBERS_DH =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(TYPE)
                    .forMethods("DHPublicNumbers")
                    .shouldBeDetectedAs(new KeyActionFactory<>(KeyAction.Action.GENERATION))
                    .withAnyParameters()
                    .buildForContext(new PublicKeyContext(KeyContext.Kind.DH))
                    .inBundle(() -> "CryptographyDiffieHellman")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> PRIVATE_NUMBERS_DH =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(TYPE)
                    .forMethods("DHPrivateNumbers")
                    .shouldBeDetectedAs(new KeyActionFactory<>(KeyAction.Action.GENERATION))
                    .withAnyParameters()
                    .buildForContext(new PrivateKeyContext(KeyContext.Kind.DH))
                    .inBundle(() -> "CryptographyDiffieHellman")
                    .withoutDependingDetectionRules();

    @Unmodifiable
    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(GENERATION_DH, PUBLIC_NUMBERS_DH, PRIVATE_NUMBERS_DH);
    }
}
