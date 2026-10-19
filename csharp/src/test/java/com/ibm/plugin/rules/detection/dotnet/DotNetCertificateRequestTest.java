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

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.engine.detection.DetectionStore;
import com.ibm.engine.language.csharp.CSharpCheck;
import com.ibm.engine.language.csharp.CSharpScanContext;
import com.ibm.engine.language.csharp.CSharpSymbol;
import com.ibm.engine.language.csharp.tree.CSharpTree;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.Padding;
import com.ibm.plugin.CSharpVerifier;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.junit.jupiter.api.Test;

/**
 * Covers {@code new CertificateRequest(...)} and {@code X509SignatureGenerator}: both RSA and ECDsa
 * overloads, a {@code PublicKey} overload, an {@code X500DistinguishedName} subject, a weak hash,
 * keyword arguments out of declared order, a hash that only the caller knows, and a key created
 * inside the call.
 *
 * <p>A request is modelled as a {@code Sign} operation whose children are the hash and, for RSA,
 * the padding. The two cases that matter most assert absence: an ECDsa request must not acquire a
 * padding, and an unresolvable hash must leave the digest off rather than be guessed.
 */
class DotNetCertificateRequestTest extends TestBase {

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/dotnet/DotNetCertificateRequestTestFile.cs", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {
        assertThat(nodes).hasSize(1);
        final INode node = nodes.get(0);

        switch (findingId) {
            // new CertificateRequest("CN=test", rsa, SHA256, Pkcs1)
            case 0 -> assertSigning(node, "PKCS1", "SHA-256");
            // X500DistinguishedName subject, SHA384 and PSS
            case 1 -> assertSigning(node, "PSS", "SHA-384");
            // the ECDsa overload has no padding, and none may be invented
            case 2 -> assertSigning(node, null, "SHA-256");
            // the PublicKey overload
            case 3 -> assertSigning(node, null, "SHA-512");
            // a weak hash is reported as written, not corrected
            case 4 -> assertSigning(node, "PKCS1", "SHA-1");
            // keyword arguments written padding, hashAlgorithm, key — not the declared order
            case 5 -> assertSigning(node, "PSS", "SHA-256");
            // the hash is a method parameter: absent, the padding still reported
            case 6 -> assertSigning(node, "PKCS1", null);
            // RSA.Create(3072) written inside the call is its own finding, reported first
            case 7 -> assertThat(node.asString()).isEqualTo("RSA-3072");
            // ... followed by the request that it feeds
            case 8 -> assertSigning(node, "PKCS1", "SHA-256");
            // X509SignatureGenerator.CreateForRSA(rsa, Pss): padding only, the hash comes later
            case 9 -> assertSigning(node, "PSS", null);
            // X509SignatureGenerator.CreateForECDsa(ecdsa)
            case 10 -> assertThat(node.asString()).isEqualTo("ECDSA");
            default -> throw new IllegalStateException("Unexpected findingId: " + findingId);
        }
    }

    /** Asserts a Sign operation and its two children, where {@code null} means absent. */
    private static void assertSigning(
            @Nonnull INode node,
            @Nullable String expectedPadding,
            @Nullable String expectedDigest) {
        assertThat(node.asString()).isEqualTo("SIGN");
        assertChild(node, Padding.class, expectedPadding);
        assertChild(node, MessageDigest.class, expectedDigest);
    }
}
