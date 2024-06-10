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
package com.ibm.plugin.rules.detection.bc.asymmetricblockcipher;

import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.IDetectionContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Unmodifiable;
import org.sonar.plugins.java.api.tree.Tree;

public final class BcAsymCipherEngine {

    private BcAsymCipherEngine() {
        // nothing
    }

    private static final List<String> cipherEnginesList =
            Arrays.asList(
                    "ElGamalEngine",
                    "NaccacheSternEngine",
                    "NTRUEngine",
                    "RSABlindedEngine",
                    "RSABlindingEngine",
                    "RSAEngine");

    private static @NotNull List<IDetectionRule<Tree>> constructors(
            @Nullable IDetectionContext detectionValueContext) {
        List<IDetectionRule<Tree>> constructorsList = new LinkedList<>();
        IDetectionContext context =
                detectionValueContext != null
                        ? detectionValueContext
                        : new CipherContext(CipherContext.Kind.ASYMMETRIC_CIPHER_ENGINE);

        for (String cipherEngine : cipherEnginesList) {
            switch (cipherEngine) {
                case "ElGamalEngine":
                    constructorsList.add(
                            new DetectionRuleBuilder<Tree>()
                                    .createDetectionRule()
                                    .forObjectTypes(
                                            "org.bouncycastle.crypto.engines." + cipherEngine)
                                    .forConstructor()
                                    .shouldBeDetectedAs(new ValueActionFactory<>("ElGamal"))
                                    .withoutParameters()
                                    .buildForContext(context)
                                    .inBundle(() -> "BcAsymCipherEngine")
                                    .withDependingDetectionRules(BcAsymCipherInit.rules()));
                    break;
                case "NaccacheSternEngine":
                    constructorsList.add(
                            new DetectionRuleBuilder<Tree>()
                                    .createDetectionRule()
                                    .forObjectTypes(
                                            "org.bouncycastle.crypto.engines." + cipherEngine)
                                    .forConstructor()
                                    .shouldBeDetectedAs(new ValueActionFactory<>("NaccacheStern"))
                                    .withoutParameters()
                                    .buildForContext(context)
                                    .inBundle(() -> "BcAsymCipherEngine")
                                    .withDependingDetectionRules(BcAsymCipherInit.rules()));
                    break;
                case "NTRUEngine":
                    constructorsList.add(
                            new DetectionRuleBuilder<Tree>()
                                    .createDetectionRule()
                                    .forObjectTypes(
                                            "org.bouncycastle.crypto.engines." + cipherEngine)
                                    .forConstructor()
                                    .shouldBeDetectedAs(new ValueActionFactory<>("NTRU"))
                                    .withoutParameters()
                                    .buildForContext(context)
                                    .inBundle(() -> "BcAsymCipherEngine")
                                    .withDependingDetectionRules(BcAsymCipherInit.rules()));
                    break;
                case "RSAEngine",
                        "RSABlindedEngine",
                        "RSABlindingEngine": // TODO: Should I distinguish these RSA cases?
                    constructorsList.add(
                            new DetectionRuleBuilder<Tree>()
                                    .createDetectionRule()
                                    .forObjectTypes(
                                            "org.bouncycastle.crypto.engines." + cipherEngine)
                                    .forConstructor()
                                    .shouldBeDetectedAs(new ValueActionFactory<>("RSA"))
                                    .withoutParameters()
                                    .buildForContext(context)
                                    .inBundle(() -> "BcAsymCipherEngine")
                                    .withDependingDetectionRules(BcAsymCipherInit.rules()));
                    break;
                default:
                    break;
            }
        }
        return constructorsList;
    }

    @Unmodifiable
    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return rules(null);
    }

    @Unmodifiable
    @Nonnull
    public static List<IDetectionRule<Tree>> rules(
            @Nullable IDetectionContext detectionValueContext) {
        return constructors(detectionValueContext);
    }
}
