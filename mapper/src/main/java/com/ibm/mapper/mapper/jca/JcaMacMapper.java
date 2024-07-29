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
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.HMAC;
import com.ibm.mapper.model.PasswordBasedEncryption;
import com.ibm.mapper.utils.DetectionLocation;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Optional;

public class JcaMacMapper implements IMapper {

    @Nonnull
    @Override
    public Optional<? extends Algorithm> parse(
            @Nullable final String str, @Nonnull DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }

        // check if it is pbe
        JcaPasswordBasedEncryptionMapper pbeMapper = new JcaPasswordBasedEncryptionMapper();
        Optional<PasswordBasedEncryption> pbeOptional = pbeMapper.parse(str, detectionLocation);
        if (pbeOptional.isPresent()) {
            // pbe
            return pbeOptional;
        }

        if (str.toLowerCase().contains("with")) {
            return Optional.empty();
        }

        final String messageDigestStr =
                str.substring(str.toLowerCase().trim().indexOf("Hmac".toLowerCase()) + 4)
                        .replace("-", "");

        JcaMessageDigestMapper jcaMessageDigestMapper = new JcaMessageDigestMapper();
        return jcaMessageDigestMapper.parse(messageDigestStr, detectionLocation).map(HMAC::new);
    }
}
