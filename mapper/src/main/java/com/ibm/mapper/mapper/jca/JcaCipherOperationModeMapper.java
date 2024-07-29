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
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.functionality.Decapsulate;
import com.ibm.mapper.model.functionality.Decrypt;
import com.ibm.mapper.model.functionality.Encapsulate;
import com.ibm.mapper.model.functionality.Encrypt;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class JcaCipherOperationModeMapper implements IMapper {

    @Nonnull
    @Override
    public Optional<? extends INode> parse(
            @Nullable String str, @Nonnull DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }
        try {
            /* Constant used to initialize cipher to decryption mode.
             *
             * ENCRYPT_MODE = 1;
             * DECRYPT_MODE = 2;
             * WRAP_MODE = 3;
             * UNWRAP_MODE = 4;
             *
             * PUBLIC_KEY = 1;
             * PRIVATE_KEY = 2;
             * SECRET_KEY = 3;
             */
            int mode = Integer.parseInt(str);
            return switch (mode) {
                case 1 -> Optional.of(new Encrypt(detectionLocation));
                case 2 -> Optional.of(new Decrypt(detectionLocation));
                case 3 -> Optional.of(new Encapsulate(detectionLocation));
                case 4 -> Optional.of(new Decapsulate(detectionLocation));
                default -> Optional.empty();
            };

        } catch (NumberFormatException e) {
            return Optional.empty();
        }
    }
}
