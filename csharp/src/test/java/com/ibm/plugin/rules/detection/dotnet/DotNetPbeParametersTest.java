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
import com.ibm.engine.model.context.KeyContext;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.NumberOfIterations;
import com.ibm.mapper.model.PasswordBasedEncryption;
import com.ibm.plugin.CSharpVerifier;
import com.ibm.plugin.TestBase;
import java.util.List;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.junit.jupiter.api.Test;

/**
 * Covers {@code new PbeParameters(...)}: each of the four {@code PbeEncryptionAlgorithm} members
 * the rule maps, the scheme each one selects, a value arriving through a {@code const} field, the
 * inline form written inside the export call, keyword arguments out of declared order, and an
 * iteration count that only the caller knows.
 *
 * <p>The AES members must yield PBES2 and {@code TripleDes3KeyPkcs12} must yield the PKCS#12
 * scheme, because the cipher is what decides the scheme. The last case asserts the iteration count
 * is absent rather than guessed, while the scheme and the hash are still reported.
 */
class DotNetPbeParametersTest extends TestBase {

    @Test
    void test() throws Exception {
        CSharpVerifier.verify("rules/detection/dotnet/DotNetPbeParametersTestFile.cs", this);
    }

    @Override
    public void asserts(
            int findingId,
            @Nonnull
                    DetectionStore<CSharpCheck, CSharpTree, CSharpSymbol, CSharpScanContext>
                            detectionStore,
            @Nonnull List<INode> nodes) {
        assertThat(detectionStore.getDetectionValueContext()).isInstanceOf(KeyContext.class);
        if (findingId == 9) {
            // Pkcs12ExportPbeParameters.Default selects a scheme that depends on the .NET version,
            // so no scheme may be reported for it
            assertThat(nodes).isEmpty();
            return;
        }
        assertThat(nodes).hasSize(1);
        final INode node = nodes.get(0);
        assertThat(node.getKind()).isEqualTo(PasswordBasedEncryption.class);

        switch (findingId) {
            // new PbeParameters(Aes256Cbc, SHA256, 100000)
            case 0 -> assertScheme(node, "PBES2", "AES-256-CBC", "SHA-256", 100000);
            // a weak hash and a low count are reported as written, not corrected
            case 1 -> assertScheme(node, "PBES2", "AES-128-CBC", "SHA-1", 2000);
            // iteration count from a local aliasing a const field
            case 2 -> assertScheme(node, "PBES2", "AES-192-CBC", "SHA-384", 600000);
            // the PKCS#12 scheme, not PBES2
            case 3 -> assertScheme(node, "PKCS12", "DESede168-CBC", "SHA-1", 2048);
            // created inside rsa.ExportEncryptedPkcs8PrivateKey(...)
            case 4 -> assertScheme(node, "PBES2", "AES-256-CBC", "SHA-512", 210000);
            // keyword arguments written in the reverse of the declared order
            case 5 -> assertScheme(node, "PBES2", "AES-256-CBC", "SHA-256", 50000);
            // iteration count is a method parameter: absent, the rest still reported
            case 6 -> assertScheme(node, "PBES2", "AES-256-CBC", "SHA-256", null);
            // cert.ExportPkcs12(Pkcs12ExportPbeParameters.Pbes2Aes256Sha256, ...): the enum member
            // names cipher and hash, but not an iteration count
            case 7 -> assertScheme(node, "PBES2", "AES-256-CBC", "SHA-256", null);
            case 8 -> assertScheme(node, "PKCS12", "DESede168-CBC", "SHA-1", null);
            default -> throw new IllegalStateException("Unexpected findingId: " + findingId);
        }
    }

    /** Asserts the scheme name and its three children, where {@code null} means absent. */
    private static void assertScheme(
            @Nonnull INode node,
            @Nonnull String expectedScheme,
            @Nonnull String expectedCipher,
            @Nullable String expectedDigest,
            @Nullable Integer expectedIterations) {
        assertThat(node.asString()).startsWith(expectedScheme);
        assertChild(node, BlockCipher.class, expectedCipher);
        assertChild(node, MessageDigest.class, expectedDigest);
        assertChild(node, NumberOfIterations.class, expectedIterations);
    }
}
