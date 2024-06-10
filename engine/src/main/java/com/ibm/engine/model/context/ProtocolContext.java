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
import org.jetbrains.annotations.NotNull;

public class ProtocolContext implements IDetectionContext, ISupportKind<ProtocolContext.Kind> {

    public enum Kind {
        TLS,
        NONE,
    }

    @Nonnull private final ProtocolContext.Kind kind;

    public ProtocolContext(@Nonnull ProtocolContext.Kind kind) {
        this.kind = kind;
    }

    public ProtocolContext() {
        this.kind = ProtocolContext.Kind.NONE;
    }

    @NotNull @Override
    public Class<? extends IDetectionContext> type() {
        return ProtocolContext.class;
    }

    @NotNull @Override
    public Kind kind() {
        return this.kind;
    }
}
