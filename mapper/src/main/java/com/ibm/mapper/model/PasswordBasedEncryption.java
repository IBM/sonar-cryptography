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

public class PasswordBasedEncryption extends Algorithm {
    public PasswordBasedEncryption(
            @Nonnull Algorithm algorithm, @Nonnull DetectionLocation detectionLocation) {
        super(algorithm, detectionLocation, PasswordBasedEncryption.class);
    }

    public PasswordBasedEncryption(
            @Nonnull Algorithm algorithm,
            @Nonnull MessageDigest digest,
            @Nonnull Mac pseudoRandomFunction,
            @Nonnull DetectionLocation detectionLocation) {
        super(algorithm, detectionLocation, PasswordBasedEncryption.class);
        this.append(digest);
        this.append(pseudoRandomFunction);
    }

    public PasswordBasedEncryption(
            @Nonnull Algorithm algorithm,
            @Nonnull MessageDigest digest,
            @Nonnull Algorithm encryptionAlgorithm,
            @Nonnull DetectionLocation detectionLocation) {
        super(algorithm, detectionLocation, PasswordBasedEncryption.class);
        this.append(digest);
        this.append(encryptionAlgorithm);
    }

    @Nonnull
    public Optional<MessageDigest> getDigest() {
        INode node = this.getChildren().get(MessageDigest.class);
        if (node == null) {
            return Optional.empty();
        }
        return Optional.of((MessageDigest) node);
    }

    @Nonnull
    public Optional<Mac> getPseudoRandomFunction() {
        INode node = this.getChildren().get(Mac.class);
        if (node == null) {
            return Optional.empty();
        }
        return Optional.of((Mac) node);
    }

    @Nonnull
    public Optional<Algorithm> getEncryptionAlgorithm() {
        INode node = this.getChildren().get(Algorithm.class);
        if (node == null) {
            return Optional.empty();
        }
        return Optional.of((Algorithm) node);
    }
}
