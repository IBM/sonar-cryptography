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
import com.ibm.engine.model.context.KeyContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.IterationCountFactory;
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;

/**
 * Detection rules for {@code PbeParameters} in System.Security.Cryptography.
 *
 * <p>{@code PbeParameters} is the one object that states how an exported key or certificate is
 * password-protected. It is handed to {@code AsymmetricAlgorithm.ExportEncryptedPkcs8PrivateKey},
 * {@code X509Certificate2.ExportPkcs12}, {@code Pkcs12Builder} and {@code
 * Pkcs8PrivateKeyInfo.Encrypt}, and its constructor takes the three facts a bill of materials needs
 * about that protection:
 *
 * <ul>
 *   <li>{@code PbeEncryptionAlgorithm encryptionAlgorithm} — the cipher: {@code Aes128Cbc}, {@code
 *       Aes192Cbc}, {@code Aes256Cbc} or {@code TripleDes3KeyPkcs12}
 *   <li>{@code HashAlgorithmName hashAlgorithm} — the hash behind the key derivation
 *   <li>{@code int iterationCount} — the PBKDF2 or PKCS#12 iteration count
 * </ul>
 *
 * <p>{@code X509Certificate2.ExportPkcs12} also accepts a {@code Pkcs12ExportPbeParameters} enum
 * member in place of a {@code PbeParameters} object. That member names the cipher and the hash
 * together, so it is detected at the export call itself ({@code PKCS12_EXPORT} below).
 *
 * <h2>Why the cipher is the root of the finding</h2>
 *
 * <p>The cipher decides which password-based scheme this is. The three AES values are PKCS#5 PBES2
 * (PBKDF2 with the named hash as its pseudo-random function), while {@code TripleDes3KeyPkcs12} is
 * the older PKCS#12 scheme of RFC 7292. A rule that fixed the root to one of them would mislabel
 * the other, so the {@code encryptionAlgorithm} argument is detected as the root and {@code
 * CSharpKeyContextTranslator} picks the matching scheme from its value, in the same way {@code
 * PycaKDF} lets its first parameter decide. The hash and the iteration count are children of that
 * root.
 *
 * <h2>Uncertain values</h2>
 *
 * <p>When the cipher argument is not a value this engine can resolve, for example a parameter of
 * the enclosing method, nothing is reported at all, because there is no root to attach the hash and
 * the iteration count to. That is deliberate: a password-based scheme guessed from nothing would be
 * worse than none. A resolved cipher with an unresolvable hash or iteration count is reported
 * without the missing child.
 */
@SuppressWarnings("java:S1192")
public final class DotNetPbeParameters extends DetectionRuleSet<CSharpTree> {

    // new PbeParameters(encryptionAlgorithm, hashAlgorithm, iterationCount)
    private static final IDetectionRule<CSharpTree> PBE_PARAMETERS =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("PbeParameters")
                    .forMethods("<init>")
                    .withNamedMethodParameter("encryptionAlgorithm", "PbeEncryptionAlgorithm")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withNamedMethodParameter("hashAlgorithm", "HashAlgorithmName")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(0)
                    .withNamedMethodParameter("iterationCount", "int")
                    .shouldBeDetectedAs(new IterationCountFactory<>())
                    .asChildOfParameterWithId(0)
                    .buildForContext(new KeyContext(Map.of("kind", "PBE")))
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // cert.ExportPkcs12(Pkcs12ExportPbeParameters.X, password). The overloads that take a
    // PbeParameters object are covered by PBE_PARAMETERS where that object is created.
    private static final IDetectionRule<CSharpTree> PKCS12_EXPORT =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("ExportPkcs12")
                    .withNamedMethodParameter("exportParameters", "Pkcs12ExportPbeParameters")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .withNamedMethodParameter("password", MethodMatcher.ANY)
                    .buildForContext(new KeyContext(Map.of("kind", "PBE")))
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    @Nonnull
    @Override
    protected List<IDetectionRule<CSharpTree>> buildRules() {
        return List.of(PBE_PARAMETERS, PKCS12_EXPORT);
    }
}
