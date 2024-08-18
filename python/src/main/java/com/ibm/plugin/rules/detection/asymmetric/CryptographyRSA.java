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

import com.ibm.engine.model.CipherAction;
import com.ibm.engine.model.KeyAction;
import com.ibm.engine.model.SignatureAction;
import com.ibm.engine.model.Size;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.PrivateKeyContext;
import com.ibm.engine.model.context.PublicKeyContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.CipherActionFactory;
import com.ibm.engine.model.factory.KeyActionFactory;
import com.ibm.engine.model.factory.KeySizeFactory;
import com.ibm.engine.model.factory.SignatureActionFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import com.ibm.plugin.rules.detection.hash.CryptographyHash;
import org.jetbrains.annotations.Unmodifiable;
import org.sonar.plugins.python.api.tree.Tree;

import javax.annotation.Nonnull;
import java.util.List;
import java.util.Map;

import static com.ibm.engine.detection.MethodMatcher.ANY;

@SuppressWarnings("java:S1192")
public final class CryptographyRSA {

    private CryptographyRSA() {
        // private
    }

    private static final String PADDING_TYPE = "cryptography.hazmat.primitives.asymmetric.padding";
    private static final String HASH_TYPE = "cryptography.hazmat.primitives.*";
    private static final String RSA_TYPE = "cryptography.hazmat.primitives.asymmetric.rsa";

    private static final IDetectionRule<Tree> MGF1 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(PADDING_TYPE)
                    .forMethods("MGF1")
                    .withMethodParameter(HASH_TYPE) // This "type" accepts both hashes
                    // and pre-hashes
                    .addDependingDetectionRules(CryptographyHash.rules())
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "CryptographyRSAMGF1")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> PSS =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(PADDING_TYPE)
                    .forMethods("PSS")
                    .shouldBeDetectedAs(
                            new SignatureActionFactory<>(SignatureAction.Action.PADDING))
                    .withMethodParameter(ANY)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .addDependingDetectionRules(List.of(MGF1))
                    .withMethodParameter(ANY)
                    .buildForContext(new SignatureContext(SignatureContext.Kind.PSS))
                    .inBundle(() -> "CryptographyRSATypes")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> PKCS1v15 =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(PADDING_TYPE)
                    .forMethods("PKCS1v15")
                    .shouldBeDetectedAs(
                            new SignatureActionFactory<>(SignatureAction.Action.PADDING))
                    .withAnyParameters()
                    .buildForContext(new SignatureContext(SignatureContext.Kind.PKCS1v15))
                    .inBundle(() -> "CryptographyRSATypes")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> OAEP =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(PADDING_TYPE)
                    .forMethods("OAEP")
                    .shouldBeDetectedAs(new ValueActionFactory<>("OAEP"))
                    .withMethodParameter(ANY)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .addDependingDetectionRules(List.of(MGF1))
                    .withMethodParameter(HASH_TYPE) // This "type" accepts both hashes
                    // and pre-hashes
                    .addDependingDetectionRules(
                            CryptographyHash
                                    .rules()) // The parameter of sign can either be an immediate
                    // hash, or a hash enclosed in the pre-hash
                    .withMethodParameter(ANY)
                    .buildForContext(new CipherContext(Map.of(
                            "kind", "padding"
                    )))
                    .inBundle(() -> "CryptographyRSATypes")
                    .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> SIGN_RSA =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(
                            "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key")
                    .forMethods("sign")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withMethodParameter(ANY)
                    .withMethodParameter("cryptography.hazmat.primitives.asymmetric.padding.*")
                    .addDependingDetectionRules(
                            List.of(
                                    PSS,
                                    PKCS1v15)) // For signatures, padding can only be PSS or PKCSv15
                    .withMethodParameter(
                            HASH_TYPE) // This "type" accepts both hashes and pre-hashes
                    .addDependingDetectionRules(
                            CryptographyHash
                                    .rules()) // The parameter of sign can either be an immediate
                    // hash, or a hash enclosed in the pre-hash
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "CryptographyRSAOperation")
                    .withoutDependingDetectionRules();

    private final static IDetectionRule<Tree> DECRYPT_RSA = new DetectionRuleBuilder<Tree>()
                .createDetectionRule()
                .forObjectTypes(
                        "cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key")
                .forMethods("decrypt")
                .shouldBeDetectedAs(new CipherActionFactory<>(CipherAction.Action.DECRYPT))
                .withMethodParameter(ANY)
                .withMethodParameter("cryptography.hazmat.primitives.asymmetric.padding.*")
                .addDependingDetectionRules(
                        List.of(OAEP, PKCS1v15)) // For encryption/decryption, padding can only be OAEP or PKCSv15
                .buildForContext(new CipherContext(Map.of("algorithm", "RSA")))
                .inBundle(() -> "Pyca")
                .withoutDependingDetectionRules();

    private static final IDetectionRule<Tree> GENERATION_RSA =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(RSA_TYPE)
                    .forMethods("generate_private_key")
                    .withMethodParameter(ANY)
                    .withMethodParameter("int")
                    .shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))
                    .buildForContext(new PrivateKeyContext(Map.of("algorithm", "RSA")))
                    .inBundle(() -> "Pyca")
                    .withDependingDetectionRules(
                            List.of(
                                    SIGN_RSA /*,VERIFY_RSA*/, DECRYPT_RSA));

    private static final IDetectionRule<Tree> PUBLIC_NUMBERS_RSA =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(RSA_TYPE)
                    .forMethods("RSAPublicNumbers")
                    .shouldBeDetectedAs(new KeyActionFactory<>(KeyAction.Action.GENERATION))
                    .withAnyParameters()
                    .buildForContext(new PublicKeyContext(KeyContext.Kind.RSA))
                    .inBundle(() -> "CryptographyRSA")
                    .withDependingDetectionRules(List.of(SIGN_RSA /*, VERIFY_RSA*/, DECRYPT_RSA));

    private static final IDetectionRule<Tree> PRIVATE_NUMBERS_RSA =
            new DetectionRuleBuilder<Tree>()
                    .createDetectionRule()
                    .forObjectTypes(RSA_TYPE)
                    .forMethods("RSAPrivateNumbers")
                    .shouldBeDetectedAs(new KeyActionFactory<>(KeyAction.Action.GENERATION))
                    .withAnyParameters()
                    .buildForContext(new PrivateKeyContext(KeyContext.Kind.RSA))
                    .inBundle(() -> "CryptographyRSA")
                    .withDependingDetectionRules(List.of(SIGN_RSA /*, VERIFY_RSA*/, DECRYPT_RSA));

    @Unmodifiable
    @Nonnull
    public static List<IDetectionRule<Tree>> rules() {
        return List.of(GENERATION_RSA, PUBLIC_NUMBERS_RSA, PRIVATE_NUMBERS_RSA);
    }
}
