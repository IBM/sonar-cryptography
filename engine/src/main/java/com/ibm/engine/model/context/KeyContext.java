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
package com.ibm.engine.model.context;

import javax.annotation.Nonnull;

@SuppressWarnings("java:S115")
public class KeyContext implements IDetectionContext, ISupportKind<KeyContext.Kind> {
    public enum Kind {
        KDF,
        KEM,
        DES,
        DESede,
        DH,
        DH_FULL,
        DSA,
        EC,
        PBE,
        RSA,
        X25519,
        X448,
        Ed25519,
        Ed448,
        Fernet,
        CHACHA20POLY1305,
        AESGCM,
        AESGCMIV,
        AESOCB3,
        AESSIV,
        AESCCM,
        PBKDF2HMAC,
        SCRYPT,
        ConcatKDFHash,
        ConcatKDFHMAC,
        HKDF,
        HKDFExpand,
        KBKDFHMAC,
        KBKDFCMAC,
        X963KDF,
        NONE,
        UNKNOWN;
    }

    @Nonnull private final Kind kind;

    public KeyContext(@Nonnull Kind kind) {
        this.kind = kind;
    }

    public KeyContext() {
        this.kind = Kind.NONE;
    }

    @Nonnull
    public Kind kind() {
        return kind;
    }

    @Nonnull
    @Override
    public Class<? extends IDetectionContext> type() {
        return KeyContext.class;
    }
}
