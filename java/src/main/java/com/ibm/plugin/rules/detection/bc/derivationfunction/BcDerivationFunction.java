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
package com.ibm.plugin.rules.detection.bc.derivationfunction;

import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.bc.BouncyCastleInfoMap;
import com.ibm.plugin.rules.detection.bc.digest.BcDigests;
import com.ibm.plugin.rules.detection.bc.mac.BcMac;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import javax.annotation.Nonnull;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Unmodifiable;
import org.sonar.plugins.java.api.tree.Tree;

public final class BcDerivationFunction {

    private BcDerivationFunction() {
        // nothing
    }

    private static BouncyCastleInfoMap digestDerivationFunctionMap = new BouncyCastleInfoMap();
    private static BouncyCastleInfoMap macDerivationFunctionMap = new BouncyCastleInfoMap();

    static {
        /*
         * When no name is explicitly defined, it is because I haven't
         * found a "good" standardized name for the algorithm
         */
        digestDerivationFunctionMap
                .putKey("BrokenKDF2BytesGenerator")
                .putName("KDF2")
                .putType("org.bouncycastle.jce.provider.");
        digestDerivationFunctionMap
                .putKey("ConcatenationKDFGenerator")
                .putType("org.bouncycastle.crypto.agreement.kdf.");
        digestDerivationFunctionMap
                .putKey("DHKEKGenerator")
                .putType("org.bouncycastle.crypto.agreement.kdf.");
        digestDerivationFunctionMap
                .putKey("ECDHKEKGenerator")
                .putType("org.bouncycastle.crypto.agreement.kdf.");
        digestDerivationFunctionMap
                .putKey("GSKKFDGenerator")
                .putType("org.bouncycastle.crypto.agreement.kdf.");
        digestDerivationFunctionMap
                .putKey("HKDFBytesGenerator")
                .putName("HKDF")
                .putType("org.bouncycastle.crypto.generators.");
        digestDerivationFunctionMap
                .putKey("KDF1BytesGenerator")
                .putName("KDF1")
                .putType("org.bouncycastle.crypto.generators.");
        digestDerivationFunctionMap
                .putKey("KDF2BytesGenerator")
                .putName("KDF2")
                .putType("org.bouncycastle.crypto.generators.");
        digestDerivationFunctionMap
                .putKey("MGF1BytesGenerator")
                .putName("MGF1")
                .putType("org.bouncycastle.crypto.generators.");

        macDerivationFunctionMap.putKey("KDFCounterBytesGenerator");
        macDerivationFunctionMap.putKey("KDFDoublePipelineIterationBytesGenerator");
        macDerivationFunctionMap.putKey("KDFFeedbackBytesGenerator");
    }

    private static @NotNull List<IDetectionRule<Tree>> simpleConstructors() {

        List<IDetectionRule<Tree>> constructorsList = new LinkedList<>();

        for (Map.Entry<String, BouncyCastleInfoMap.Info> entry :
                digestDerivationFunctionMap.entrySet()) {
            String generator = entry.getKey();
            String generatorName =
                    digestDerivationFunctionMap.getDisplayName(generator, "Generator");
            String type = entry.getValue().getType();
            constructorsList.add(
                    new DetectionRuleBuilder<Tree>()
                            .createDetectionRule()
                            .forObjectTypes(type + generator)
                            .forConstructor()
                            .shouldBeDetectedAs(new ValueActionFactory<>(generatorName))
                            .withMethodParameter("org.bouncycastle.crypto.Digest")
                            .addDependingDetectionRules(BcDigests.rules())
                            .buildForContext(new KeyContext(KeyContext.Kind.KDF))
                            // TODO: .withDependingDetectionRules(DerivationFunctionInit.rules()));
                            .inBundle(() -> "Bc")
                            .withoutDependingDetectionRules());
        }

        for (Map.Entry<String, BouncyCastleInfoMap.Info> entry :
                macDerivationFunctionMap.entrySet()) {
            String generator = entry.getKey();
            String generatorName =
                    macDerivationFunctionMap.getDisplayName(generator, "BytesGenerator");
            constructorsList.add(
                    new DetectionRuleBuilder<Tree>()
                            .createDetectionRule()
                            .forObjectTypes("org.bouncycastle.crypto.generators." + generator)
                            .forConstructor()
                            .shouldBeDetectedAs(new ValueActionFactory<>(generatorName))
                            .withMethodParameter("org.bouncycastle.crypto.Mac")
                            .addDependingDetectionRules(BcMac.rules())
                            .buildForContext(new KeyContext(KeyContext.Kind.KDF))
                            // TODO: .withDependingDetectionRules(DerivationFunctionInit.rules()));
                            .inBundle(() -> "Bc")
                            .withoutDependingDetectionRules());
        }

        return constructorsList;
    }

    private static @NotNull List<IDetectionRule<Tree>> specialConstructors() {
        List<IDetectionRule<Tree>> constructorsList = new LinkedList<>();

        constructorsList.add(
                new DetectionRuleBuilder<Tree>()
                        .createDetectionRule()
                        .forObjectTypes(
                                "org.bouncycastle.crypto.engines.EthereumIESEngine$HandshakeKDFFunction")
                        .forConstructor()
                        .shouldBeDetectedAs(new ValueActionFactory<>("HandshakeKDF"))
                        .withMethodParameter("int")
                        .withMethodParameter("org.bouncycastle.crypto.Digest")
                        .addDependingDetectionRules(BcDigests.rules())
                        .buildForContext(new KeyContext(KeyContext.Kind.KDF))
                        // TODO: .withDependingDetectionRules(DerivationFunctionInit.rules()));
                        .inBundle(() -> "Bc")
                        .withoutDependingDetectionRules());

        return constructorsList;
    }

    @Unmodifiable
    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return Stream.of(simpleConstructors().stream(), specialConstructors().stream())
                .flatMap(i -> i)
                .toList();
    }
}
