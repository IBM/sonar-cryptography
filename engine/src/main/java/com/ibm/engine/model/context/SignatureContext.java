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

public class SignatureContext implements IDetectionContext, ISupportKind<SignatureContext.Kind> {
    public enum Kind {
        PSS,
        MGF1,
        PKCS1v15,
        DSA,
        RSA,
        EdDSA,
        SIGNATURE_NAME,
        SIGNING_STATUS,
        DIGEST_MESSAGE_WRAPPER,
        ALGORITHM_AND_HASH_WRAPPER,
        NONE
    }

    @Nonnull private final Kind kind;

    public SignatureContext(@Nonnull Kind kind) {
        this.kind = kind;
    }

    public SignatureContext() {
        this.kind = Kind.NONE;
    }

    @Nonnull
    public Kind kind() {
        return kind;
    }

    @Nonnull
    @Override
    public Class<? extends IDetectionContext> type() {
        return SignatureContext.class;
    }
}
