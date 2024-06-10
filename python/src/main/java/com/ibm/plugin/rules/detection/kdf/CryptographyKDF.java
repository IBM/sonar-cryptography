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
package com.ibm.plugin.rules.detection.kdf;

import static com.ibm.engine.detection.MethodMatcher.ANY;

import com.ibm.engine.model.AlgorithmParameter;
import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.AlgorithmParameterFactory;
import com.ibm.engine.model.factory.KeyActionFactory;
import com.ibm.engine.model.factory.KeySizeFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import javax.annotation.Nonnull;
import org.jetbrains.annotations.Unmodifiable;
import org.sonar.plugins.python.api.tree.Tree;

@SuppressWarnings("java:S1192")
public final class CryptographyKDF {

    private CryptographyKDF() {
        // private
    }

    private static final String HASH_TYPE = "cryptography.hazmat.primitives.hashes.*";
    private static final String KDF_TYPE_PREFIX = "cryptography.hazmat.primitives.kdf.";

    private static final IDetectionRule<Tree> X963KDF =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(KDF_TYPE_PREFIX + "x963kdf")
                    .forMethods("X963KDF")
                    .shouldBeDetectedAs(new KeyActionFactory<>(KeyAction.Action.KDF))
                    .withMethodParameter(HASH_TYPE) // Accepts only hashes (not pre-hashes)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                    .withMethodParameter(ANY)
                    .buildForContext(new KeyContext(KeyContext.Kind.X963KDF))
                    .inBundle(() -> "CryptographyKDF")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> KBKDFCMAC =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(KDF_TYPE_PREFIX + "kbkdf")
                    .forMethods("KBKDFCMAC")
                    .shouldBeDetectedAs(new KeyActionFactory<>(KeyAction.Action.KDF))
                    .withMethodParameter("cryptography.hazmat.primitives.ciphers.algorithms.*")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter(ANY) // TODO: a Mode could be detected here
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                    .withMethodParameter(ANY)
                    .withMethodParameter(ANY)
                    .withMethodParameter(ANY)
                    .withMethodParameter(ANY)
                    .withMethodParameter(ANY)
                    .withMethodParameter(ANY)
                    .buildForContext(new KeyContext(KeyContext.Kind.KBKDFCMAC))
                    .inBundle(() -> "CryptographyKDF")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> KBKDFHMAC =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(KDF_TYPE_PREFIX + "kbkdf")
                    .forMethods("KBKDFHMAC")
                    .shouldBeDetectedAs(new KeyActionFactory<>(KeyAction.Action.KDF))
                    .withMethodParameter(HASH_TYPE) // Accepts only hashes (not pre-hashes)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter(ANY) // TODO: a Mode could be detected here
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                    .withMethodParameter(ANY)
                    .withMethodParameter(ANY)
                    .withMethodParameter(ANY)
                    .withMethodParameter(ANY)
                    .withMethodParameter(ANY)
                    .withMethodParameter(ANY)
                    .buildForContext(new KeyContext(KeyContext.Kind.KBKDFHMAC))
                    .inBundle(() -> "CryptographyKDF")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> HKDF_EXPAND =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(KDF_TYPE_PREFIX + "hkdf")
                    .forMethods("HKDFExpand")
                    .shouldBeDetectedAs(new KeyActionFactory<>(KeyAction.Action.KDF))
                    .withMethodParameter(HASH_TYPE) // Accepts only hashes (not pre-hashes)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                    .withMethodParameter(ANY)
                    .buildForContext(new KeyContext(KeyContext.Kind.HKDFExpand))
                    .inBundle(() -> "CryptographyKDF")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> HKDF =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(KDF_TYPE_PREFIX + "hkdf")
                    .forMethods("HKDF")
                    .shouldBeDetectedAs(new KeyActionFactory<>(KeyAction.Action.KDF))
                    .withMethodParameter(HASH_TYPE) // Accepts only hashes (not pre-hashes)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                    .withMethodParameter(ANY)
                    .withMethodParameter(ANY)
                    .buildForContext(new KeyContext(KeyContext.Kind.HKDF))
                    .inBundle(() -> "CryptographyKDF")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> CONCAT_KDF_HMAC =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(KDF_TYPE_PREFIX + "concatkdf")
                    .forMethods("ConcatKDFHMAC")
                    .shouldBeDetectedAs(new KeyActionFactory<>(KeyAction.Action.KDF))
                    .withMethodParameter(HASH_TYPE) // Accepts only hashes (not pre-hashes)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                    .withMethodParameter(ANY)
                    .withMethodParameter(ANY)
                    .buildForContext(new KeyContext(KeyContext.Kind.ConcatKDFHMAC))
                    .inBundle(() -> "CryptographyKDF")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> CONCAT_KDF =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(KDF_TYPE_PREFIX + "concatkdf")
                    .forMethods("ConcatKDFHash")
                    .shouldBeDetectedAs(new KeyActionFactory<>(KeyAction.Action.KDF))
                    .withMethodParameter(HASH_TYPE) // Accepts only hashes (not pre-hashes)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                    .withMethodParameter(ANY)
                    .buildForContext(new KeyContext(KeyContext.Kind.ConcatKDFHash))
                    .inBundle(() -> "CryptographyKDF")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> SCRYPT =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(KDF_TYPE_PREFIX + "scrypt")
                    .forMethods("Scrypt")
                    .shouldBeDetectedAs(new KeyActionFactory<>(KeyAction.Action.KDF))
                    .withMethodParameter(ANY)
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                    .withMethodParameter("int")
                    .withMethodParameter("int")
                    .withMethodParameter("int")
                    .buildForContext(new KeyContext(KeyContext.Kind.SCRYPT))
                    .inBundle(() -> "CryptographyKDF")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> PBKDF2 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(KDF_TYPE_PREFIX + "pbkdf2")
                    .forMethods("PBKDF2HMAC")
                    .shouldBeDetectedAs(new KeyActionFactory<>(KeyAction.Action.KDF))
                    .withMethodParameter(HASH_TYPE) // Accepts only hashes (not pre-hashes)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                    .withMethodParameter(ANY)
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(
                            new AlgorithmParameterFactory<>(AlgorithmParameter.Kind.ITERATIONS))
                    .buildForContext(new KeyContext(KeyContext.Kind.PBKDF2HMAC))
                    .inBundle(() -> "CryptographyKDF")
                    .withoutDependingDetectionRules();

    @Unmodifiable
    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(
                PBKDF2,
                SCRYPT,
                CONCAT_KDF,
                CONCAT_KDF_HMAC,
                HKDF,
                HKDF_EXPAND,
                KBKDFHMAC,
                KBKDFCMAC,
                X963KDF);
    }
}
