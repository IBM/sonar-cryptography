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
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.mapper.utils.Utils;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class JcaModeMapper implements IMapper {
    private static final List<String> validValues =
            List.of("NONE", "CBC", "CCM", "CFB", "CTR", "CTS", "ECB", "GCM", "OFB", "PCBC");

    public JcaModeMapper() {
        // nothing
    }

    @Nonnull
    @Override
    public Optional<Mode> parse(
            @Nullable final String str,
            @Nonnull final DetectionLocation detectionLocation,
            @Nonnull final Configuration configuration) {
        if (str == null) {
            return Optional.empty();
        }
        // get explicit block size
        Optional<BlockSize> optionalBlockSize =
                Utils.extractNumberFormString(str)
                        .map(blockSizeStr -> new BlockSize(blockSizeStr, detectionLocation))
                        .map(
                                blockSize -> {
                                    blockSize.apply(configuration);
                                    return blockSize;
                                });
        // remove numeric values
        String modeString = str.replaceAll("\\d", "");

        if (!reflectValidValues(modeString)) {
            return Optional.empty();
        }

        Mode mode =
                optionalBlockSize
                        .map(blockSize -> new Mode(modeString, blockSize, detectionLocation))
                        .orElseGet(() -> new Mode(modeString, detectionLocation));
        mode.apply(configuration);
        return Optional.of(mode);
    }

    private boolean reflectValidValues(@Nonnull String str) {
        return validValues.stream().anyMatch(str::equalsIgnoreCase);
    }
}
