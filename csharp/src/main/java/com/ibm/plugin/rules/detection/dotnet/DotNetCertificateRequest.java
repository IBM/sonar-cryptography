/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2024 PQCA
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
package com.ibm.plugin.rules.detection.dotnet;

import com.ibm.engine.detection.MethodMatcher;
import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.engine.model.SignatureAction;
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.PaddingFactory;
import com.ibm.engine.model.factory.SignatureActionFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;

/**
 * Detection rules for how a certificate is signed, in {@code
 * System.Security.Cryptography.X509Certificates}.
 *
 * <p>A certificate signing request or a self-signed certificate states its signature algorithm at
 * creation time, not at the later {@code Create} or {@code CreateSelfSigned} call, so that is where
 * the rules look:
 *
 * <ul>
 *   <li>{@code new CertificateRequest(subjectName, key, hashAlgorithm[, padding])} — the hash the
 *       certificate is signed over and, for an RSA key, the {@code RSASignaturePadding}
 *   <li>{@code X509SignatureGenerator.CreateForRSA(key, signaturePadding)} — the padding of a
 *       signature produced by an RSA generator
 *   <li>{@code X509SignatureGenerator.CreateForECDsa(key)} — an ECDSA signature generator
 * </ul>
 *
 * <h2>How the request is modelled</h2>
 *
 * <p>A {@code CertificateRequest} exists to be signed, and the hash and padding passed to its
 * constructor are exactly the ones used for that signature, so the constructor is reported as a
 * {@code Sign} operation with the hash and padding as its children. This is the same shape the
 * {@code SignData} and {@code SignHash} rules of {@link DotNetRSA} and {@link DotNetECDsa} produce.
 * The later {@code Create}/{@code CreateSelfSigned} calls carry no further cryptographic
 * information, so they are deliberately not matched: doing so would report the same signature
 * twice.
 *
 * <h2>Overloads</h2>
 *
 * <p>One rule covers every overload of the constructor. The subject is either a {@code string} or
 * an {@code X500DistinguishedName}, and the key is an {@code RSA}, an {@code ECDsa} or a {@code
 * PublicKey}; none of those is captured. The {@code RSASignaturePadding} only exists on the RSA
 * overloads, so it is optional. In the {@code PublicKey} overload the second parameter is named
 * {@code publicKey} rather than {@code key}, which only matters for a call that passes it by
 * keyword; written positionally, as it almost always is, it binds correctly.
 *
 * <h2>What is not captured</h2>
 *
 * <p>Which key signs the request is not linked here. The key is an argument, and the engine does
 * not connect an argument variable to the finding that created it, so an {@code RSA.Create(2048)}
 * that feeds the request is reported separately. When a hash or padding argument cannot be resolved
 * the corresponding child is left off rather than guessed.
 */
@SuppressWarnings("java:S1192")
public final class DotNetCertificateRequest extends DetectionRuleSet<CSharpTree> {

    // new CertificateRequest(subjectName, key, hashAlgorithm [, padding])
    private static final IDetectionRule<CSharpTree> CERTIFICATE_REQUEST =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("CertificateRequest")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withNamedMethodParameter("subjectName", MethodMatcher.ANY)
                    .withNamedMethodParameter("key", MethodMatcher.ANY)
                    .withNamedMethodParameter("hashAlgorithm", "HashAlgorithmName")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withOptionalNamedMethodParameter("padding", "RSASignaturePadding")
                    .shouldBeDetectedAs(new PaddingFactory<>())
                    .asChildOfParameterWithId(-1)
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // X509SignatureGenerator.CreateForRSA(key, signaturePadding)
    private static final IDetectionRule<CSharpTree> CREATE_FOR_RSA =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("X509SignatureGenerator")
                    .forMethods("CreateForRSA")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withNamedMethodParameter("key", MethodMatcher.ANY)
                    .withNamedMethodParameter("signaturePadding", "RSASignaturePadding")
                    .shouldBeDetectedAs(new PaddingFactory<>())
                    .asChildOfParameterWithId(-1)
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // X509SignatureGenerator.CreateForECDsa(key)
    private static final IDetectionRule<CSharpTree> CREATE_FOR_ECDSA =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("X509SignatureGenerator")
                    .forMethods("CreateForECDsa")
                    .shouldBeDetectedAs(new ValueActionFactory<>("ECDSA"))
                    .withNamedMethodParameter("key", MethodMatcher.ANY)
                    .buildForContext(new KeyContext(Map.of("kind", "ECDSA")))
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    @Nonnull
    @Override
    protected List<IDetectionRule<CSharpTree>> buildRules() {
        return List.of(CERTIFICATE_REQUEST, CREATE_FOR_RSA, CREATE_FOR_ECDSA);
    }
}
