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

public class DigestContext implements IDetectionContext, ISupportKind<DigestContext.Kind> {

    // Currently, Kind contain all the types of hashes in Python's cryptography library.
    // This means that Kind is library sepcific, which is not optimal.
    // TODO: If at some point Kind would have to be used for another language/library, Kind would
    // have to be changed to contain library-independent values. Additionally, a new mapping layer
    // would have to be built between each library hash values and these library-independent values.
    public enum Kind {
        NONE,
        MGF1,
        CRAMER_SHOUP,
        NTRU,
        SHA1,
        SHA512_224,
        SHA512_256,
        SHA224,
        SHA256,
        SHA384,
        SHA512,
        SHA3_224,
        SHA3_256,
        SHA3_384,
        SHA3_512,
        SHAKE128,
        SHAKE256,
        MD5,
        BLAKE2b,
        BLAKE2s,
        SM3
    }

    @Nonnull private final Kind kind;

    public DigestContext() {
        this.kind = Kind.NONE;
    }

    public DigestContext(@Nonnull Kind kind) {
        this.kind = kind;
    }

    @Nonnull
    public Kind kind() {
        return kind;
    }

    @Nonnull
    @Override
    public Class<? extends IDetectionContext> type() {
        return DigestContext.class;
    }
}
