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
package com.ibm.output.cyclondx.builder;

import com.ibm.mapper.model.INode;
import javax.annotation.Nullable;

public class AlgorithmVariant {
    @Nullable INode algorithm;
    @Nullable INode keySize;
    @Nullable INode mode;
    @Nullable INode padding;
    @Nullable INode curve;

    protected AlgorithmVariant(
            @Nullable INode algorithm,
            @Nullable INode keySize,
            @Nullable INode mode,
            @Nullable INode padding,
            @Nullable INode curve) {
        this.algorithm = algorithm;
        this.keySize = keySize;
        this.mode = mode;
        this.padding = padding;
        this.curve = curve;
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        if (algorithm == null) {
            return "";
        }

        final String algorithmString = algorithm.asString();
        // check for signature algo
        builder.append(algorithmString.trim().toLowerCase());

        if (keySize != null
                && !keySize.asString().isBlank()
                && !algorithmString.matches(".*\\d.*")) {
            builder.append("-").append(keySize.asString());
        }
        if (mode != null && !mode.asString().isBlank()) {
            builder.append("-").append(mode.asString().toLowerCase());
        }
        if (padding != null && !padding.asString().isBlank()) {
            builder.append("-").append(padding.asString().toLowerCase());
        }
        if (curve != null && !curve.asString().isBlank()) {
            builder.append("-").append(curve.asString().trim());
        }
        return builder.toString();
    }
}
