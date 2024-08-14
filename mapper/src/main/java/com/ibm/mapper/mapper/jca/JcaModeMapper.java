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
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.Mode;
import com.ibm.mapper.model.mode.CBC;
import com.ibm.mapper.model.mode.CCM;
import com.ibm.mapper.model.mode.CFB;
import com.ibm.mapper.model.mode.CTR;
import com.ibm.mapper.model.mode.CTS;
import com.ibm.mapper.model.mode.ECB;
import com.ibm.mapper.model.mode.GCM;
import com.ibm.mapper.model.mode.OFB;
import com.ibm.mapper.model.mode.PCBC;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.mapper.utils.Utils;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class JcaModeMapper implements IMapper {

    public JcaModeMapper() {
        // nothing
    }

    @Nonnull
    @Override
    public Optional<Mode> parse(
            @Nullable final String str, @Nonnull final DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }
        // get explicit block size
        Optional<BlockSize> optionalBlockSize =
                Utils.extractNumberFormString(str)
                        .map(blockSizeStr -> new BlockSize(blockSizeStr, detectionLocation));
        // remove numeric values
        String modeString = str.replaceAll("\\d", "");
        return map(modeString, detectionLocation)
                .map(
                        mode -> {
                            optionalBlockSize.ifPresent(mode::put);
                            return mode;
                        });
    }

    @Nonnull
    private Optional<Mode> map(@Nonnull String mode, @Nonnull DetectionLocation detectionLocation) {
        return switch (mode.toUpperCase().trim()) {
            case "ECB" -> Optional.of(new ECB(detectionLocation));
            case "CBC" -> Optional.of(new CBC(detectionLocation));
            case "PCBC" -> Optional.of(new PCBC(detectionLocation));
            case "CFB" -> Optional.of(new CFB(detectionLocation));
            case "OFB" -> Optional.of(new OFB(detectionLocation));
            case "CTR" -> Optional.of(new CTR(detectionLocation));
            case "CTS" -> Optional.of(new CTS(detectionLocation));
            case "GCM" -> Optional.of(new GCM(detectionLocation));
            case "CCM" -> Optional.of(new CCM(detectionLocation));
            default -> Optional.empty();
        };
    }
}
