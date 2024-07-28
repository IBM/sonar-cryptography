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

import java.util.Optional;
import javax.annotation.Nonnull;

/** PBKDF */
public class KeyDerivationFunction extends Algorithm {

    KeyDerivationFunction(
            @Nonnull Algorithm algorithm, @Nonnull final Class<? extends Algorithm> asKind) {
        super(algorithm, algorithm.detectionLocation, asKind);
    }

    public KeyDerivationFunction(@Nonnull Algorithm algorithm) {
        super(algorithm, algorithm.detectionLocation, KeyDerivationFunction.class);
    }

    public KeyDerivationFunction(
            @Nonnull Algorithm algorithm,
            @Nonnull SaltLength saltLength,
            @Nonnull KeyLength keyLength) {
        super(algorithm, algorithm.detectionLocation, KeyDerivationFunction.class);
        this.append(saltLength);
        this.append(keyLength);
    }

    @Nonnull
    public Optional<SaltLength> getSalt() {
        INode node = this.getChildren().get(SaltLength.class);
        if (node == null) {
            return Optional.empty();
        }
        return Optional.of((SaltLength) node);
    }
}
