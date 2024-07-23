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
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.MaskGenerationFunction;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import org.jetbrains.annotations.NotNull;

public class JcaMGFMapper implements IMapper {

    private static final List<String> validValues = List.of("MGF1");

    @Nonnull
    @Override
    public Optional<MaskGenerationFunction> parse(
            @Nullable String str,
            @Nonnull DetectionLocation detectionLocation,
            @Nonnull Configuration configuration) {
        if (str == null) {
            return Optional.empty();
        }

        if (!reflectValidValues(str)) {
            return Optional.empty();
        }

        JcaBaseAlgorithmMapper jcaBaseAlgorithmMapper = new JcaBaseAlgorithmMapper();
        Optional<Algorithm> algorithmOptional =
                jcaBaseAlgorithmMapper.parse(str, detectionLocation, configuration);
        if (algorithmOptional.isEmpty()) {
            return Optional.empty();
        }

        final MaskGenerationFunction mgf = new MaskGenerationFunction(algorithmOptional.get());
        return Optional.of(mgf);
    }

    private boolean reflectValidValues(@NotNull String str) {
        return validValues.stream().anyMatch(str::equalsIgnoreCase);
    }
}
