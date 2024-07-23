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

public class OptimalAsymmetricEncryptionPadding extends Padding {
    public OptimalAsymmetricEncryptionPadding(
            @Nonnull Padding padding) {
        super(padding, padding.detectionLocation, OptimalAsymmetricEncryptionPadding.class);
    }

    public OptimalAsymmetricEncryptionPadding(
            @Nonnull Padding padding,
            @Nonnull MessageDigest messageDigest) {
        super(padding, padding.detectionLocation, OptimalAsymmetricEncryptionPadding.class);
        this.append(messageDigest);
    }

    public OptimalAsymmetricEncryptionPadding(
            @Nonnull Padding padding,
            @Nonnull MessageDigest messageDigest,
            @Nonnull MaskGenerationFunction maskGenerationFunction) {
        super(padding, padding.detectionLocation, OptimalAsymmetricEncryptionPadding.class);
        this.append(messageDigest);
        this.append(maskGenerationFunction);
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
    public Optional<MaskGenerationFunction> getMGF() {
        INode node = this.getChildren().get(MaskGenerationFunction.class);
        if (node == null) {
            return Optional.empty();
        }
        return Optional.of((MaskGenerationFunction) node);
    }
}
