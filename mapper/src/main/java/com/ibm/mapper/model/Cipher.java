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
package com.ibm.mapper.model;

import javax.annotation.Nonnull;
import java.util.Optional;

public class Cipher extends Algorithm {

    protected Cipher(@Nonnull Algorithm algorithm, @Nonnull final Class<? extends Cipher> asKind) {
        super(algorithm, asKind);
    }

    protected Cipher(
            @Nonnull Algorithm algorithm,
            @Nonnull Mode mode,
            @Nonnull final Class<? extends Cipher> asKind) {
        super(algorithm, asKind);
        this.append(mode);
    }

    public Cipher(@Nonnull Algorithm algorithm) {
        super(algorithm, Cipher.class);
    }

    public Cipher(
            @Nonnull Algorithm algorithm,
            @Nonnull Mode mode,
            @Nonnull Padding padding,
            @Nonnull final Class<? extends Cipher> asKind) {
        super(algorithm, asKind);
        this.append(mode);
        this.append(padding);
    }

    public Cipher(@Nonnull Algorithm algorithm, @Nonnull Mode mode) {
        super(algorithm, Cipher.class);
        this.append(mode);
    }

    public Cipher(@Nonnull Algorithm algorithm, @Nonnull Mode mode, @Nonnull Padding padding) {
        super(algorithm, Cipher.class);
        this.append(mode);
        this.append(padding);
    }

    @Nonnull
    public Optional<Mode> getMode() {
        INode node = this.getChildren().get(Mode.class);
        if (node == null) {
            return Optional.empty();
        }
        return Optional.of((Mode) node);
    }

    @Nonnull
    public Optional<Padding> getPadding() {
        INode node = this.getChildren().get(Padding.class);
        if (node == null) {
            return Optional.empty();
        }
        return Optional.of((Padding) node);
    }

    @Nonnull
    public Optional<DigestSize> getDigestSize() {
        INode node = this.getChildren().get(DigestSize.class);
        if (node == null) {
            return Optional.empty();
        }
        return Optional.of((DigestSize) node);
    }
}
