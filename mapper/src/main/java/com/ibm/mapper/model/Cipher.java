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

import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/**
 * <a
 * href="https://docs.oracle.com/javase/8/docs/technotes/guides/security/StandardNames.html#Cipher">Source</a>
 */
public class Cipher extends Algorithm {

    protected Cipher(
            @Nonnull Algorithm algorithm,
            @Nullable Mode mode,
            @Nullable Padding padding,
            @Nonnull DetectionLocation detectionLocation,
            @Nonnull final Class<? extends Cipher> asKind) {
        super(algorithm, detectionLocation, asKind);
        if (mode != null) {
            this.append(mode);
        }
        if (padding != null) {
            this.append(padding);
        }
    }

    public Cipher(@Nonnull Algorithm algorithm, @Nonnull DetectionLocation detectionLocation) {
        super(algorithm, detectionLocation, Cipher.class);
    }

    public Cipher(
            @Nonnull Algorithm algorithm,
            @Nullable Mode mode,
            @Nullable Padding padding,
            @Nonnull DetectionLocation detectionLocation) {
        super(algorithm, detectionLocation, Cipher.class);
        if (mode != null) {
            this.append(mode);
        }
        if (padding != null) {
            this.append(padding);
        }
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
}
