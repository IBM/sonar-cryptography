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
import com.ibm.engine.model.context.CipherContext;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Detection rules for {@code System.Security.Cryptography.Xml}.
 *
 * <p>XML Signature and XML Encryption name each algorithm by a W3C URI, which code writes either as
 * a literal or as a constant of {@code SignedXml} or {@code EncryptedXml}. Three places state one,
 * and each is a rule here:
 *
 * <ul>
 *   <li>{@code reference.DigestMethod = …} — the digest of a signed reference
 *   <li>{@code signedInfo.SignatureMethod = …} — the signature algorithm: RSA, DSA, ECDSA or an
 *       HMAC, with its digest
 *   <li>{@code new EncryptionMethod(algorithm)} and {@code encryptionMethod.KeyAlgorithm = …} — the
 *       cipher of encrypted data, or the key-transport algorithm of an encrypted key
 * </ul>
 *
 * <p>The URI is read by {@code DotNetXmlAlgorithmUris}, so a URI that is not in its table, a
 * canonicalization or transform URI, or a value that only the caller knows produces no node.
 *
 * <h2>The chained form</h2>
 *
 * <p>The most common way to set the signature method is {@code signedXml.SignedInfo.SignatureMethod
 * = …}, a property of a property. The converter turns such an assignment into the same synthetic
 * setter as a single-level one, with the whole chain, here {@code signedXml.SignedInfo}, as its
 * receiver. These rules match any receiver, so they see it. A setter rule that attaches to a
 * tracked variable does not, because the chain never equals a variable name.
 *
 * <p>The receiver of each setter is a variable, not a type name, so it is matched as {@link
 * MethodMatcher#ANY}. The property names are specific enough to the XML classes, and an unrelated
 * class with a {@code DigestMethod} or {@code SignatureMethod} property only produces a finding if
 * its value is one of the known URIs.
 */
@SuppressWarnings("java:S1192")
public final class DotNetXml extends DetectionRuleSet<CSharpTree> {

    // reference.DigestMethod = SignedXml.XmlDsigSHA256Url
    private static final IDetectionRule<CSharpTree> REFERENCE_DIGEST_METHOD =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("set_DigestMethod")
                    .withMethodParameter(MethodMatcher.ANY)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(new DigestContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // signedInfo.SignatureMethod = SignedXml.XmlDsigRSASHA256Url
    private static final IDetectionRule<CSharpTree> SIGNATURE_METHOD =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("set_SignatureMethod")
                    .withMethodParameter(MethodMatcher.ANY)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // new EncryptionMethod(EncryptedXml.XmlEncAES256Url)
    private static final IDetectionRule<CSharpTree> ENCRYPTION_METHOD =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("EncryptionMethod")
                    .forMethods("<init>")
                    .withNamedMethodParameter("algorithm", "string")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    // encryptionMethod.KeyAlgorithm = EncryptedXml.XmlEncAES256Url
    private static final IDetectionRule<CSharpTree> ENCRYPTION_KEY_ALGORITHM =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes(MethodMatcher.ANY)
                    .forMethods("set_KeyAlgorithm")
                    .withMethodParameter(MethodMatcher.ANY)
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .buildForContext(new CipherContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    @Nonnull
    @Override
    protected List<IDetectionRule<CSharpTree>> buildRules() {
        return List.of(
                REFERENCE_DIGEST_METHOD,
                SIGNATURE_METHOD,
                ENCRYPTION_METHOD,
                ENCRYPTION_KEY_ALGORITHM);
    }
}
