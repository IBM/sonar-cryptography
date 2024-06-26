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
package com.ibm.plugin.rules.detection.symmetric;

import com.ibm.engine.model.CipherAction;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.CipherActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.padding.CryptographyPadding;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import javax.annotation.Nonnull;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Unmodifiable;
import org.sonar.plugins.python.api.tree.Tree;

@SuppressWarnings({"java:S2386", "java:S1192"})
public final class CryptographyCipher {

    private CryptographyCipher() {
        // private
    }

    public static final List<String> blockCiphers =
            Arrays.asList(
                    "AES",
                    "AES128",
                    "AES256",
                    "Camellia",
                    "TripleDES",
                    "CAST5",
                    "SEED",
                    "SM4",
                    "Blowfish",
                    "IDEA");
    public static final List<String> streamCiphers = Arrays.asList("ChaCha20", "ARC4");

    public static @NotNull List<String> cipherAlgorithms() {
        List<String> cipherAlgorithms = new LinkedList<>(blockCiphers);
        cipherAlgorithms.addAll(streamCiphers);
        return cipherAlgorithms;
    }

    public static final List<String> modes =
            Arrays.asList("CBC", "CTR", "OFB", "CFB", "CFB8", "GCM", "XTS", "ECB");

    private static final IDetectionRule<Tree> ENCRYPT_CIPHER =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("cryptography.hazmat.primitives.ciphers.Cipher")
                    .forMethods("encryptor")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.ENCRYPT))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "CryptographyCipherOperation")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> DECRYPT_CIPHER =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("cryptography.hazmat.primitives.ciphers.Cipher")
                    .forMethods("decryptor")
                    .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.DECRYPT))
                    .withAnyParameters()
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "CryptographyCipherOperation")
                    .withoutDependingDetectionRules();

    private static @NotNull List<IDetectionRule<Tree>> followingNewCipherRules() {
        final List<IDetectionRule<Tree>> encryptionRules =
                new LinkedList<>(List.of(DECRYPT_CIPHER, ENCRYPT_CIPHER));
        encryptionRules.addAll(CryptographyPadding.rules());
        return encryptionRules;
    }

    private static final IDetectionRule<Tree> NEW_CIPHER =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes("cryptography.hazmat.primitives.ciphers")
                    .forMethods("Cipher")
                    .withMethodParameter("cryptography.hazmat.primitives.ciphers.algorithms.*")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .addDependingDetectionRules(followingNewCipherRules())
                    // TODO: If it is written as `algorithms.AES(os.urandom(32))`, we can obtain the
                    //  key size
                    .withMethodParameter("cryptography.hazmat.primitives.ciphers.modes.*")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "CryptographyCipher")
                    .withoutDependingDetectionRules();

    // TODO: writting
    //  `followingNewCipherRules` will duplicate them because we have two parameter detections. This
    //  is probably a bug I should create an issue for. In the meantime, an easy fix is to add the
    //  depending detection rules to only one parameter instead of the method detection.

    @Unmodifiable
    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(NEW_CIPHER);
    }
}
