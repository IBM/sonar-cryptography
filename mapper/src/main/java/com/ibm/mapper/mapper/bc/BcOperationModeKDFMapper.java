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
package com.ibm.mapper.mapper.bc;

import com.ibm.mapper.mapper.IMapper;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.algorithms.KDF1;
import com.ibm.mapper.model.algorithms.KDF2;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

/** Mapper for the {@code counterStart} argument of {@code HandshakeKDFFunction} */
public class BcOperationModeKDFMapper implements IMapper {

    @Nonnull
    @Override
    public Optional<? extends INode> parse(
            @Nullable String str, @Nonnull DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }
        try {
            /* Constant used in `counterStart`
             *
             * KDF1 = 0;
             * KDF2 = 1;
             */
            int counterStart = Integer.parseInt(str);
            return switch (counterStart) {
                case 0 -> Optional.of(new KDF1(detectionLocation));
                case 1 -> Optional.of(new KDF2(detectionLocation));
                default -> Optional.empty();
            };

        } catch (NumberFormatException e) {
            return Optional.empty();
        }
    }
}
