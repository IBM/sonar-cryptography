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
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.ValueActionFactory;
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Detection rules for the certificate thumbprint methods of {@code X509Certificate} in {@code
 * System.Security.Cryptography.X509Certificates}.
 *
 * <p>A certificate hash is how code identifies a certificate, for pinning or for a lookup, and the
 * digest it uses is a cryptographic choice a bill of materials should record:
 *
 * <ul>
 *   <li>{@code GetCertHash(HashAlgorithmName)}, {@code GetCertHashString(HashAlgorithmName)} and
 *       {@code TryGetCertHash(HashAlgorithmName, Span<byte>, out int)} state the digest in their
 *       argument
 *   <li>{@code GetCertHash()} and {@code GetCertHashString()} state none, and are SHA-1 by
 *       definition: the parameterless forms return the classic SHA-1 thumbprint
 * </ul>
 *
 * <h2>Two rules, one per form</h2>
 *
 * <p>The repository convention is one rule per method, because two rules on the same method would
 * both match and report one call twice. These two rules are the exception, and cannot overlap. The
 * first requires the {@code hashAlgorithm} argument, so a call without it is rejected by the
 * argument binder; the second matches only a call with no arguments at all. Every call therefore
 * matches exactly one of them.
 *
 * <p>The digest is the finding itself, with no operation attached: a thumbprint is a hash of the
 * certificate, so there is nothing to encrypt, sign or verify. An argument that is not a resolvable
 * {@code HashAlgorithmName}, such as a method parameter, produces no finding rather than a guessed
 * digest.
 *
 * <p>The receiver is a certificate variable, not a type name, so it is matched as {@link
 * MethodMatcher#ANY}; the method names are distinctive enough to identify the call. The {@code
 * Thumbprint} property is also SHA-1, but it is a property read and is not visible to this engine.
 */
@SuppressWarnings("java:S1192")
public final class DotNetCertificateHash extends DetectionRuleSet<CSharpTree> {

    // cert.GetCertHash(hashAlgorithm) / cert.GetCertHashString(hashAlgorithm) /
    // cert.TryGetCertHash(hashAlgorithm, destination, out bytesWritten)
    private static final IDetectionRule<CSharpTree> CERT_HASH_WITH_ALGORITHM =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("GetCertHash", "GetCertHashString", "TryGetCertHash")
                    .withNamedMethodParameter("hashAlgorithm", "HashAlgorithmName")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withOptionalNamedMethodParameter("destination", MethodMatcher.ANY)
                    .withOptionalNamedMethodParameter("bytesWritten", MethodMatcher.ANY)
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // cert.GetCertHash() / cert.GetCertHashString() — the SHA-1 thumbprint
    private static final IDetectionRule<CSharpTree> CERT_HASH_SHA1 =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("GetCertHash", "GetCertHashString")
                    .shouldBeDetectedAs(new ValueActionFactory<>("SHA1"))
                    .withoutParameters()
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    @Nonnull
    @Override
    protected List<IDetectionRule<CSharpTree>> buildRules() {
        return List.of(CERT_HASH_WITH_ALGORITHM, CERT_HASH_SHA1);
    }
}
