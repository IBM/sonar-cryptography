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
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.MacContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.IterationCountFactory;
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Detection rules for {@code System.Security.Cryptography.Pkcs}.
 *
 * <p>Covers the members of this namespace that state a hash, and optionally an iteration count, as
 * a plain argument:
 *
 * <ul>
 *   <li>{@code Pkcs12Builder.SealWithMac(password, hashAlgorithm, iterationCount)} — the integrity
 *       MAC of a PKCS#12 (PFX) file. It is an HMAC over the named hash, keyed through a PKCS#12
 *       derivation that runs for the given number of iterations. A SHA-1 MAC with a low count is
 *       the old default of many tools, which is why the pair is worth recording.
 *   <li>{@code Rfc3161TimestampRequest.CreateFromData(data, hashAlgorithm, …)}, {@code
 *       CreateFromHash(hash, hashAlgorithm, …)} and {@code CreateFromSignerInfo(signerInfo,
 *       hashAlgorithm, …)} — the digest a timestamp request is made over.
 * </ul>
 *
 * <h2>The hash is the root of the finding</h2>
 *
 * <p>In each rule the {@code hashAlgorithm} argument is the root detection, so a call whose hash is
 * not a resolvable {@code HashAlgorithmName} produces no finding rather than a guessed one. For
 * {@code SealWithMac} the root is read as an HMAC, because the context is a MAC, and the iteration
 * count is attached to it. {@code CreateFromHash} has a second overload taking an {@code Oid}
 * instead of a {@code HashAlgorithmName}; that form is not matched.
 *
 * <h2>Not covered</h2>
 *
 * <p>The password-based encryption of a PFX or a PKCS#8 key is stated by a {@code PbeParameters}
 * object, which {@link DotNetPbeParameters} already detects where it is created, so {@code
 * Pkcs12Builder.AddSafeContentsEncrypted}, {@code Pkcs12SafeContents.AddShroudedKey} and {@code
 * Pkcs8PrivateKeyInfo.Encrypt} need no rule of their own. {@code CmsRecipient} is left out because
 * its overloads move the padding argument between positions, which the argument binder cannot tell
 * apart without type information.
 */
@SuppressWarnings("java:S1192")
public final class DotNetPkcs extends DetectionRuleSet<CSharpTree> {

    // builder.SealWithMac(password, hashAlgorithm, iterationCount)
    private static final IDetectionRule<CSharpTree> SEAL_WITH_MAC =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("SealWithMac")
                    .withNamedMethodParameter("password", MethodMatcher.ANY)
                    .withNamedMethodParameter("hashAlgorithm", "HashAlgorithmName")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withNamedMethodParameter("iterationCount", "int")
                    .shouldBeDetectedAs(new IterationCountFactory<>())
                    .asChildOfParameterWithId(1)
                    .buildForContext(new MacContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    /**
     * One rule per timestamp factory. The three differ only in the name of their first parameter,
     * which carries the data, the hash or the signer to be timestamped and is not captured.
     */
    @Nonnull
    private static IDetectionRule<CSharpTree> timestampRequest(
            @Nonnull String method, @Nonnull String firstParameter) {
        return new DetectionRuleBuilder<CSharpTree>()
                .createDetectionRule()
                .forObjectTypes("Rfc3161TimestampRequest")
                .forMethods(method)
                .withNamedMethodParameter(firstParameter, MethodMatcher.ANY)
                .withNamedMethodParameter("hashAlgorithm", "HashAlgorithmName")
                .shouldBeDetectedAs(new AlgorithmFactory<>())
                .withOptionalNamedMethodParameter("requestedPolicyId", MethodMatcher.ANY)
                .withOptionalNamedMethodParameter("nonce", MethodMatcher.ANY)
                .withOptionalNamedMethodParameter("requestSignerCertificates", MethodMatcher.ANY)
                .withOptionalNamedMethodParameter("extensions", MethodMatcher.ANY)
                .buildForContext(new DigestContext())
                .inBundle(() -> "DotNet")
                .withoutDependingDetectionRules();
    }

    @Nonnull
    @Override
    protected List<IDetectionRule<CSharpTree>> buildRules() {
        return List.of(
                SEAL_WITH_MAC,
                timestampRequest("CreateFromData", "data"),
                timestampRequest("CreateFromHash", "hash"),
                timestampRequest("CreateFromSignerInfo", "signerInfo"));
    }
}
