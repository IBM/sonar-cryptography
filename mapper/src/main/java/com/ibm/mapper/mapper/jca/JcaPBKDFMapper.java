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
import com.ibm.mapper.model.IAlgorithm;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.PasswordBasedKeyDerivationFunction;
import com.ibm.mapper.model.algorithms.PBKDF2;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class JcaPBKDFMapper implements IMapper {

    @Nonnull
    @Override
    public Optional<PasswordBasedKeyDerivationFunction> parse(
            @Nullable String str, @Nonnull DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }

        final String generalizedStr = str.toLowerCase().trim();
        if (!generalizedStr.contains("pbkdf2with")) {
            return Optional.empty();
        }

        int algoStartIndex = generalizedStr.indexOf("pbkdf2with") + 10;
        String prf = str.substring(algoStartIndex);

        final JcaMacMapper jcaMacMapper = new JcaMacMapper();
        final Optional<? extends IAlgorithm> macOptional =
                jcaMacMapper.parse(prf, detectionLocation);
        if (macOptional.isPresent() && macOptional.get() instanceof Mac hmac) {
            return macOptional.map(mac -> new PBKDF2(hmac));
        }
        return Optional.empty();
    }
}
