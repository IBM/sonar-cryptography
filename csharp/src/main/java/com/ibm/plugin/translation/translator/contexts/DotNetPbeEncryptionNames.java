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
package com.ibm.plugin.translation.translator.contexts;

import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.DESede;
import com.ibm.mapper.model.algorithms.PBES2;
import com.ibm.mapper.model.algorithms.PKCS12PBE;
import com.ibm.mapper.model.algorithms.SHA;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.mode.CBC;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;

/**
 * Maps a {@code System.Security.Cryptography.PbeEncryptionAlgorithm} member to the password-based
 * encryption scheme it selects.
 *
 * <p>The member names are those of the {@code PbeEncryptionAlgorithm} enum as the detection engine
 * resolves them, for example {@code PbeEncryptionAlgorithm.Aes256Cbc} becomes {@code "Aes256Cbc"}.
 * The three AES members select PKCS#5 PBES2 (RFC 8018) with the cipher in CBC mode; the PBKDF2
 * pseudo-random function is the {@code HashAlgorithmName} given next to it, attached separately.
 * {@code TripleDes3KeyPkcs12} selects the PKCS#12 scheme of RFC 7292
 * (pbeWithSHAAnd3-KeyTripleDES-CBC) with three-key Triple DES, whose effective key length is 168
 * bits.
 *
 * <p>The same table also resolves the members of {@code Pkcs12ExportPbeParameters}, the enum that
 * {@code X509Certificate2.ExportPkcs12} accepts in place of a {@code PbeParameters} object.
 *
 * <p>{@code Unknown}, the zero value of the enum, {@code Default}, and any other spelling yield an
 * empty result rather than a guessed scheme.
 */
public final class DotNetPbeEncryptionNames {

    private DotNetPbeEncryptionNames() {
        // utility
    }

    /**
     * Returns the scheme node, with its cipher attached, that a {@code PbeEncryptionAlgorithm}
     * member name denotes, if it is a known one.
     */
    @Nonnull
    public static Optional<INode> parse(
            @Nonnull String encryptionAlgorithmName, @Nonnull DetectionLocation detectionLocation) {
        return switch (encryptionAlgorithmName.trim()) {
            case "Aes128Cbc" -> Optional.of(pbes2WithAes(128, detectionLocation));
            case "Aes192Cbc" -> Optional.of(pbes2WithAes(192, detectionLocation));
            case "Aes256Cbc" -> Optional.of(pbes2WithAes(256, detectionLocation));
            case "TripleDes3KeyPkcs12" -> {
                final PKCS12PBE scheme = new PKCS12PBE(detectionLocation);
                scheme.put(new DESede(168, new CBC(detectionLocation), detectionLocation));
                yield Optional.of(scheme);
            }
            // Pkcs12ExportPbeParameters (X509Certificate2.ExportPkcs12): unlike PbeParameters, the
            // member names both the cipher and the hash, so the digest is attached here. Default is
            // left unresolved on purpose, because what it selects depends on the .NET version.
            case "Pbes2Aes256Sha256" -> {
                final INode scheme = pbes2WithAes(256, detectionLocation);
                scheme.put(new SHA2(256, detectionLocation));
                yield Optional.of(scheme);
            }
            case "Pkcs12TripleDesSha1" -> {
                final PKCS12PBE scheme = new PKCS12PBE(detectionLocation);
                scheme.put(new DESede(168, new CBC(detectionLocation), detectionLocation));
                scheme.put(new SHA(detectionLocation));
                yield Optional.of(scheme);
            }
            default -> Optional.empty();
        };
    }

    @Nonnull
    private static INode pbes2WithAes(int keyBits, @Nonnull DetectionLocation detectionLocation) {
        final PBES2 scheme = new PBES2(detectionLocation);
        scheme.put(new AES(keyBits, new CBC(detectionLocation), detectionLocation));
        return scheme;
    }
}
