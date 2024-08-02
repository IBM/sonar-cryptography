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
import org.jetbrains.annotations.NotNull;

public class ECAlgorithm extends Algorithm {
    private static final String NAME = "EC";

    public ECAlgorithm(@NotNull DetectionLocation detectionLocation) {
        super(NAME, detectionLocation);
    }

    public ECAlgorithm(@Nonnull EllipticCurve ellipticCurve) {
        super(NAME + "-" + ellipticCurve.asString(), ellipticCurve.detectionLocation);
        this.append(ellipticCurve);
    }

    @Nonnull
    public Optional<EllipticCurve> getCurve() {
        INode node = this.getChildren().get(EllipticCurve.class);
        if (node == null) {
            return Optional.empty();
        }
        return Optional.of((EllipticCurve) node);
    }
}
