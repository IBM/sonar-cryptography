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

import com.ibm.engine.model.context.AlgorithmParameterContext;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.bc.digest.BcDigests;
import java.util.List;
import javax.annotation.Nonnull;
import org.jetbrains.annotations.Unmodifiable;
import org.sonar.plugins.java.api.tree.Tree;

public final class BcNTRUSigningPrivateKeyParameters {

    private BcNTRUSigningPrivateKeyParameters() {
        // nothing
    }

    /*
     * This base constructor is not a CipherParameters class.
     * It is the only rule where we have to specify the context.
     */
    private static final IDetectionRule<Tree> BASE_CONSTRUCTOR_1 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(
                            "org.bouncycastle.pqc.legacy.crypto.ntru.NTRUSigningKeyGenerationParameters")
                    .forConstructor()
                    .withMethodParameter("int")
                    .withMethodParameter("int")
                    .withMethodParameter("int")
                    .withMethodParameter("int")
                    .withMethodParameter("int")
                    .withMethodParameter("double")
                    .withMethodParameter("double")
                    .withMethodParameter("double")
                    .withMethodParameter("boolean")
                    .withMethodParameter("boolean")
                    .withMethodParameter("int")
                    .withMethodParameter("org.bouncycastle.crypto.Digest")
                    .addDependingDetectionRules(
                            BcDigests.rules(new DigestContext(DigestContext.Kind.NTRU)))
                    .buildForContext(new AlgorithmParameterContext())
                    .inBundle(() -> "Bc")
                    .withoutDependingDetectionRules();

    /*
     * This base constructor is not a CipherParameters class.
     * It is the only rule where we have to specify the context.
     */
    private static final IDetectionRule<Tree> BASE_CONSTRUCTOR_2 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(
                            "org.bouncycastle.pqc.legacy.crypto.ntru.NTRUSigningKeyGenerationParameters")
                    .forConstructor()
                    .withMethodParameter("int")
                    .withMethodParameter("int")
                    .withMethodParameter("int")
                    .withMethodParameter("int")
                    .withMethodParameter("int")
                    .withMethodParameter("int")
                    .withMethodParameter("int")
                    .withMethodParameter("double")
                    .withMethodParameter("double")
                    .withMethodParameter("double")
                    .withMethodParameter("boolean")
                    .withMethodParameter("boolean")
                    .withMethodParameter("int")
                    .withMethodParameter("org.bouncycastle.crypto.Digest")
                    .addDependingDetectionRules(
                            BcDigests.rules(new DigestContext(DigestContext.Kind.NTRU)))
                    .buildForContext(new AlgorithmParameterContext())
                    .inBundle(() -> "Bc")
                    .withoutDependingDetectionRules();

    private static final List<IDetectionRule<Tree>> BASE_CONSTRUCTORS =
            List.of(BASE_CONSTRUCTOR_1, BASE_CONSTRUCTOR_2);

    private static final IDetectionRule<Tree> PRIVATE_KEY_CONSTRUCTOR_1 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(
                            "org.bouncycastle.pqc.legacy.crypto.ntru.NTRUSigningPrivateKeyParameters")
                    .forConstructor()
                    .withMethodParameter(BYTE_ARRAY_TYPE)
                    .withMethodParameter(
                            "org.bouncycastle.pqc.legacy.crypto.ntru.NTRUSigningKeyGenerationParameters")
                    .addDependingDetectionRules(BASE_CONSTRUCTORS)
                    .buildForContext(new AlgorithmParameterContext())
                    .inBundle(() -> "Bc")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> PRIVATE_KEY_CONSTRUCTOR_2 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(
                            "org.bouncycastle.pqc.legacy.crypto.ntru.NTRUSigningPrivateKeyParameters")
                    .forConstructor()
                    .withMethodParameter("java.io.InputStream")
                    .withMethodParameter(
                            "org.bouncycastle.pqc.legacy.crypto.ntru.NTRUSigningKeyGenerationParameters")
                    .addDependingDetectionRules(BASE_CONSTRUCTORS)
                    .buildForContext(new AlgorithmParameterContext())
                    .inBundle(() -> "Bc")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> PRIVATE_KEY_CONSTRUCTOR_3 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(
                            "org.bouncycastle.pqc.legacy.crypto.ntru.NTRUSigningPrivateKeyParameters")
                    .forConstructor()
                    .withMethodParameter("java.util.List")
                    .withMethodParameter(
                            "org.bouncycastle.pqc.legacy.crypto.ntru.NTRUSigningPublicKeyParameters")
                    .addDependingDetectionRules(BcNTRUSigningPublicKeyParameters.rules())
                    .buildForContext(new AlgorithmParameterContext())
                    .inBundle(() -> "Bc")
                    .withoutDependingDetectionRules();

    @Unmodifiable
    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(
                PRIVATE_KEY_CONSTRUCTOR_1, PRIVATE_KEY_CONSTRUCTOR_2, PRIVATE_KEY_CONSTRUCTOR_3);
    }
}
