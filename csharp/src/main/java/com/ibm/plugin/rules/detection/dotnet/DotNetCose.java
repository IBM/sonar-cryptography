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
import com.ibm.engine.model.context.SignatureContext;
import com.ibm.engine.model.factory.AlgorithmFactory;
import com.ibm.engine.model.factory.PaddingFactory;
import com.ibm.engine.model.factory.SignatureActionFactory;
import com.ibm.engine.rule.DetectionRuleSet;
import com.ibm.engine.rule.IDetectionRule;
import com.ibm.engine.rule.builder.DetectionRuleBuilder;
import java.util.List;
import javax.annotation.Nonnull;

/**
 * Detection rules for {@code System.Security.Cryptography.Cose}.
 *
 * <p>COSE (CBOR Object Signing and Encryption, RFC 9052) is the binary counterpart of JOSE. In .NET
 * a {@code CoseSigner} holds everything a COSE signature needs, and states it as constructor
 * arguments:
 *
 * <ul>
 *   <li>{@code CoseSigner(key, signaturePadding, hashAlgorithm[, protectedHeaders[,
 *       unprotectedHeaders]])} — the RSA overload, which names a padding as well as a hash
 *   <li>{@code CoseSigner(key, hashAlgorithm[, protectedHeaders[, unprotectedHeaders]])} — the
 *       overload for ECDSA and other keys, which names a hash only
 * </ul>
 *
 * <p>A signer exists to sign, and the hash and padding it is given are the ones used, so the
 * constructor is reported as a {@code Sign} operation with the hash and, for RSA, the padding as
 * children. That is the shape {@link DotNetCertificateRequest} produces for a certificate request.
 * The {@code CoseSign1Message.SignEmbedded} and {@code SignDetached} calls that use the signer
 * carry no further cryptographic data, so they are not matched: doing so would report the same
 * signature twice.
 *
 * <h2>One rule for two overloads</h2>
 *
 * <p>The two overloads put the hash in different positions, after the padding in the RSA one and
 * directly after the key in the other, and a rule per overload would overlap on the shared argument
 * counts and report one call twice. A single rule covers both, so the hash and padding are placed
 * by their declared types, which is how the argument binder tells them apart.
 *
 * <h2>What is not captured</h2>
 *
 * <p>The key is an argument and is not linked to the finding that created it, and the {@code
 * CoseHeaderMap} arguments can name an algorithm by a COSE identifier, which this engine cannot
 * read. When the hash or the padding cannot be resolved, the corresponding child is left off rather
 * than guessed.
 */
@SuppressWarnings("java:S1192")
public final class DotNetCose extends DetectionRuleSet<CSharpTree> {

    // new CoseSigner(key, signaturePadding, hashAlgorithm [, protectedHeaders [,
    // unprotectedHeaders]])
    // new CoseSigner(key, hashAlgorithm [, protectedHeaders [, unprotectedHeaders]])
    private static final IDetectionRule<CSharpTree> COSE_SIGNER =
            new DetectionRuleBuilder<CSharpTree>()
                    .createDetectionRule()
                    .forObjectTypes("CoseSigner")
                    .forMethods("<init>")
                    .shouldBeDetectedAs(new SignatureActionFactory<>(SignatureAction.Action.SIGN))
                    .withNamedMethodParameter("key", MethodMatcher.ANY)
                    .withNamedMethodParameter("hashAlgorithm", "HashAlgorithmName")
                    .shouldBeDetectedAs(new AlgorithmFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withOptionalNamedMethodParameter("signaturePadding", "RSASignaturePadding")
                    .shouldBeDetectedAs(new PaddingFactory<>())
                    .asChildOfParameterWithId(-1)
                    .withOptionalNamedMethodParameter("protectedHeaders", MethodMatcher.ANY)
                    .withOptionalNamedMethodParameter("unprotectedHeaders", MethodMatcher.ANY)
                    .buildForContext(new SignatureContext())
                    .inBundle(() -> "DotNet")
                    .withoutDependingDetectionRules();

    @Nonnull
    @Override
    protected List<IDetectionRule<CSharpTree>> buildRules() {
        return List.of(COSE_SIGNER);
    }
}
