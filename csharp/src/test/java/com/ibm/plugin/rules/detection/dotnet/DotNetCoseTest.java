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
 * Covers {@code new CoseSigner(...)}: both overloads, with and without header maps, a weak hash,
 * keyword arguments out of declared order, and a hash that only the caller knows.
 *
 * <p>The two overloads put the hash in different positions, after the padding in the RSA one and
 * directly after the key in the other, and one rule covers both. The RSA cases are the ones that
 * matter most: they only come out right if the argument binder can tell an {@code
 * RSASignaturePadding} from a {@code HashAlgorithmName} that sits where the rule declares the
 * other. Two cases assert absence: an ECDSA signer must not acquire a padding, and an unresolvable
 * hash must leave the digest off while the padding is still reported.
 */
class DotNetCoseTest extends TestBase {

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/dotnet/DotNetCoseTestFile.cs", this);
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
        assertThat(node.asString()).isEqualTo("SIGN");

        switch (findingId) {
            // the RSA overload: key, padding, hash
            case 0 -> assertSigning(node, "PSS", "SHA-256");
            case 1 -> assertSigning(node, "PKCS1", "SHA-384");
            // the overload for ECDSA: key, hash. No padding may be invented.
            case 2 -> assertSigning(node, null, "SHA-256");
            // the RSA overload with a protected header map
            case 3 -> assertSigning(node, "PSS", "SHA-512");
            // the ECDSA overload with both header maps
            case 4 -> assertSigning(node, null, "SHA-384");
            // a weak hash is reported as written, not corrected
            case 5 -> assertSigning(node, "PKCS1", "SHA-1");
            // keyword arguments written hash, padding, key: not the declared order
            case 6 -> assertSigning(node, "PSS", "SHA-256");
            // the hash is a method parameter: absent, the padding still reported
            case 7 -> assertSigning(node, "PSS", null);
            default -> throw new IllegalStateException("Unexpected findingId: " + findingId);
        }
    }

    /** Asserts the two children of a Sign operation, where {@code null} means absent. */
    private static void assertSigning(
            @Nonnull INode node,
            @Nullable String expectedPadding,
            @Nullable String expectedDigest) {
        assertChild(node, Padding.class, expectedPadding);
        assertChild(node, MessageDigest.class, expectedDigest);
    }
}
