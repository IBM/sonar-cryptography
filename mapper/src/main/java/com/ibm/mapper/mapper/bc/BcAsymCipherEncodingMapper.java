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
import com.ibm.mapper.model.Padding;
import com.ibm.mapper.model.PublicKeyEncryption;
import com.ibm.mapper.model.Unknown;
import com.ibm.mapper.model.padding.ISO9796Padding;
import com.ibm.mapper.model.padding.OAEP;
import com.ibm.mapper.model.padding.PKCS1;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.mapper.utils.Utils;
import java.util.Optional;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class BcAsymCipherEncodingMapper implements IMapper {

    @Override
    @Nonnull
    public Optional<? extends INode> parse(
            @Nullable String str, @Nonnull DetectionLocation detectionLocation) {
        if (str == null) {
            return Optional.empty();
        }
        return map(str, detectionLocation);
    }

    @Nonnull
    private Optional<? extends INode> map(
            @Nonnull String blockCipherString, @Nonnull DetectionLocation detectionLocation) {
        return switch (blockCipherString) {
            case "ISO9796d1Encoding" ->
                    Optional.of(
                            Utils.unknownWithPadding(
                                    new ISO9796Padding(detectionLocation),
                                    PublicKeyEncryption.class));
            case "OAEPEncoding" ->
                    Optional.of(
                            Utils.unknownWithPadding(
                                    new OAEP(detectionLocation), PublicKeyEncryption.class));
            case "PKCS1Encoding" ->
                    Optional.of(
                            Utils.unknownWithPadding(
                                    new PKCS1(detectionLocation), PublicKeyEncryption.class));
            default -> {
                Padding padding = new Padding(blockCipherString, detectionLocation);
                padding.put(new Unknown(detectionLocation));
                yield Optional.of(Utils.unknownWithPadding(padding, PublicKeyEncryption.class));
            }
        };
    }
}
