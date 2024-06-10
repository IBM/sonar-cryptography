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
package com.ibm.mapper.mapper.jca;

import com.ibm.mapper.configuration.Configuration;
import com.ibm.mapper.mapper.IMapper;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

class JcaBasePaddingMapper implements IMapper {

    private static final List<String> validValues =
            List.of(
                    "NoPadding",
                    "ISO10126Padding",
                    "OAEPPadding",
                    "PKCS1Padding",
                    "PKCS5Padding",
                    "SSL3Padding");

    public JcaBasePaddingMapper() {
        // nothing
    }

    @Nonnull
    @SuppressWarnings("OptionalUsedAsFieldOrParameterType")
    public static <T extends Padding> Optional<Padding> generalizePadding(
            @Nonnull Optional<T> optional) {
        if (optional.isEmpty()) {
            return Optional.empty();
        }
        T val = optional.get();
        return Optional.of(val);
    }

    @Nonnull
    @Override
    public Optional<Padding> parse(
            @Nullable final String str,
            @Nonnull final DetectionLocation detectionLocation,
            @Nonnull final Configuration configuration) {
        return parseAndAddChildren(str, detectionLocation, configuration, new HashMap<>());
    }

    @Nonnull
    public Optional<Padding> parseAndAddChildren(
            @Nullable final String str,
            @Nonnull final DetectionLocation detectionLocation,
            @Nonnull final Configuration configuration,
            @Nonnull Map<Class<? extends INode>, INode> children) {
        if (str == null) {
            return Optional.empty();
        }
        if (!reflectValidValues(str)) {
            return Optional.empty();
        }
        Padding padding = new Padding(str, detectionLocation, children);
        padding.apply(configuration);
        return Optional.of(padding);
    }

    private boolean reflectValidValues(@Nonnull final String str) {
        return validValues.stream().anyMatch(str::equalsIgnoreCase) || str.contains("OAEPWith");
    }
}
