/*
 * SonarQube Cryptography Plugin
 * Copyright (C) 2024 IBM
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
package com.ibm.mapper.mapper.ssl.json;

import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

@SuppressWarnings("java:S107")
public final class JsonCipherSuite {

    @Nonnull private final String ianaName;
    @Nullable private final String gnutlsName;
    @Nullable private final String opensslName;
    @Nullable private final String[] identifiers;

    @Nullable private final String kexAlgorithm;
    @Nullable private final String authAlgorithm;
    @Nullable private final String encAlgorithm;
    @Nullable private final String hashAlgorithm;

    public JsonCipherSuite(
            @Nonnull String ianaName,
            @Nullable String gnutlsName,
            @Nullable String opensslName,
            @Nullable String[] identifiers,
            @Nullable String kexAlgorithm,
            @Nullable String authAlgorithm,
            @Nullable String encAlgorithm,
            @Nullable String hashAlgorithm) {
        this.ianaName = ianaName;
        this.gnutlsName = gnutlsName;
        this.opensslName = opensslName;
        this.identifiers = identifiers;
        this.kexAlgorithm = kexAlgorithm;
        this.authAlgorithm = authAlgorithm;
        this.encAlgorithm = encAlgorithm;
        this.hashAlgorithm = hashAlgorithm;
    }

    @Nonnull
    public String getIanaName() {
        return ianaName;
    }

    @Nonnull
    public Optional<String> getGnutlsName() {
        return Optional.ofNullable(gnutlsName);
    }

    @Nonnull
    public Optional<String> getOpensslName() {
        return Optional.ofNullable(opensslName);
    }

    @Nonnull
    public Optional<String[]> getIdentifiers() {
        return Optional.ofNullable(identifiers);
    }

    @Nonnull
    public Optional<String> getKexAlgorithm() {
        return Optional.ofNullable(kexAlgorithm);
    }

    @Nonnull
    public Optional<String> getAuthAlgorithm() {
        return Optional.ofNullable(authAlgorithm);
    }

    @Nonnull
    public Optional<String> getEncAlgorithm() {
        return Optional.ofNullable(encAlgorithm);
    }

    @Nonnull
    public Optional<String> getHashAlgorithm() {
        return Optional.ofNullable(hashAlgorithm);
    }
}
