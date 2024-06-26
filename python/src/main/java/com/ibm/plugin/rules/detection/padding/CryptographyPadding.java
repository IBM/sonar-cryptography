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
package com.ibm.plugin.rules.detection.padding;

import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.KeySizeFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.symmetric.CryptographyCipher;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import javax.annotation.Nonnull;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Unmodifiable;
import org.sonar.plugins.python.api.tree.Tree;

@SuppressWarnings("java:S1192")
public final class CryptographyPadding {

    private CryptographyPadding() {
        // private
    }

    private static final List<String> paddings = Arrays.asList("PKCS7", "ANSIX923");

    private static @NotNull List<IDetectionRule<Tree>> newPadding() {
        final LinkedList<IDetectionRule<Tree>> rules = new LinkedList<>();
        // When the block size is specified using an integer
        for (String padding : paddings) {
            rules.add(
                    new DetectionRuleBuilder<Tree>()
                            .createDetectionRule()
                            .forObjectTypes("cryptography.hazmat.primitives.padding")
                            .forMethods(padding)
                            .withMethodParameter("int")
                            .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                            .buildForContext(new CipherContext(CipherContext.Kind.valueOf(padding)))
                            .inBundle(() -> "CryptographyPadding")
                            .withoutDependingDetectionRules());
        }
        // When the block size is specified using a `block_size` attribute
        for (String padding : paddings) {
            for (String cipherAlgorithm : CryptographyCipher.blockCiphers) {
                rules.add(
                        new DetectionRuleBuilder<Tree>()
                                .createDetectionRule()
                                .forObjectTypes("cryptography.hazmat.primitives.padding")
                                .forMethods(padding)
                                .withMethodParameter(
                                        "cryptography.hazmat.primitives.ciphers.algorithms."
                                                + cipherAlgorithm
                                                + ".block_size")
                                .shouldBeDetectedAs(new AlgorithmFactory<>(cipherAlgorithm))
                                .buildForContext(
                                        new CipherContext(CipherContext.Kind.valueOf(padding)))
                                .inBundle(() -> "CryptographyPadding")
                                .withoutDependingDetectionRules());
            }
        }
        return rules;
    }

    // TODO: It should be better to only detect Padding when it actually gets implied (i.e. there is
    //  `padder.update` function call). However, it does not bring much, and creates problems
    // because
    //  the type handler may not distinguish an `encryptor.update` from `padder.update`.

    @Unmodifiable
    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return newPadding();
    }
}
