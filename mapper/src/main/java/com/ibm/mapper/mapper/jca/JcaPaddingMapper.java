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

import com.ibm.mapper.mapper.IMapper;
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.padding.ISO10126;
import com.ibm.mapper.model.padding.PKCS1;
import com.ibm.mapper.model.padding.PKCS5;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class JcaPaddingMapper implements IMapper {

    @Nonnull
    @Override
    public Optional<? extends Padding> parse(
            @Nullable String str, @Nonnull DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }

        if (str.toUpperCase().contains("OAEP")) {
            final JcaOAEPPaddingMapper jcaOAEPPaddingMapper = new JcaOAEPPaddingMapper();
            return jcaOAEPPaddingMapper.parse(str, detectionLocation);
        }

        return map(str, detectionLocation);
    }

    @Nonnull
    private Optional<Padding> map(
            @Nonnull String padding, @Nonnull DetectionLocation detectionLocation) {
        return switch (padding.toUpperCase().trim()) {
            case "ISO10126PADDING" -> Optional.of(new ISO10126(detectionLocation));
            case "PKCS1PADDING" -> Optional.of(new PKCS1(detectionLocation));
            case "PKCS5PADDING" -> Optional.of(new PKCS5(detectionLocation));
            case "NOPADDING" -> Optional.empty();
            default -> Optional.of(new Padding(padding, detectionLocation));
        };
    }
}
