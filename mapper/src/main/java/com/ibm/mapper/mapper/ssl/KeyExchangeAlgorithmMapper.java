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
package com.ibm.mapper.mapper.ssl;

import com.ibm.mapper.configuration.Configuration;
import com.ibm.mapper.mapper.IMapper;
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Map;
import java.util.Optional;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public class KeyExchangeAlgorithmMapper implements IMapper {

    private final Map<String, String> nameMap = Map.of("DHE", "dh");

    @NotNull @Override
    public Optional<? extends INode> parse(
            @Nullable String str,
            @NotNull DetectionLocation detectionLocation,
            @NotNull Configuration configuration) {
        if (str == null) {
            return Optional.empty();
        }
        final String name = Optional.ofNullable(nameMap.get(str)).orElse(str);
        final Algorithm algorithm = new Algorithm(name, detectionLocation);
        return Optional.of(new KeyAgreement(algorithm));
    }
}
