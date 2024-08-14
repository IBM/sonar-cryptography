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
package com.ibm.mapper.model;

import com.ibm.mapper.ITranslator;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nonnull;

public class PasswordBasedEncryption extends Algorithm implements IPrimitive {

    public PasswordBasedEncryption(@Nonnull DetectionLocation detectionLocation) {
        super(ITranslator.UNKNOWN, PasswordBasedEncryption.class, detectionLocation);
    }

    // example: PBEWithHmacSHA1AndAES_128
    public PasswordBasedEncryption(@Nonnull Mac mac, @Nonnull Cipher cipher) {
        super(
                "PBEWith" + mac.asString() + "And" + cipher.asString(),
                PasswordBasedEncryption.class,
                mac.getDetectionContext());
        this.put(mac);
        this.put(cipher);
    }

    // example: PBEWithMD5AndDES
    public PasswordBasedEncryption(@Nonnull MessageDigest digest, @Nonnull Cipher cipher) {
        super(
                "PBEWith" + digest.asString() + "And" + cipher.asString(),
                PasswordBasedEncryption.class,
                digest.getDetectionContext());
        this.put(digest);
        this.put(cipher);
    }

    // example: PBEWithHmacSHA1
    public PasswordBasedEncryption(@Nonnull Mac mac) {
        super("PBEWith" + mac.asString(), PasswordBasedEncryption.class, mac.getDetectionContext());
        this.put(mac);
    }

    @Nonnull
    public Optional<Mac> getMac() {
        INode node = this.getChildren().get(Mac.class);
        if (node == null) {
            return Optional.empty();
        }
        return Optional.of((Mac) node);
    }

    @Nonnull
    public Optional<MessageDigest> getDigest() {
        INode node = this.getChildren().get(MessageDigest.class);
        if (node == null) {
            return Optional.empty();
        }
        return Optional.of((MessageDigest) node);
    }

    @Nonnull
    public Optional<Cipher> getCipher() {
        return this.getChildren().values().stream()
                .map(
                        n -> {
                            if (n instanceof Cipher cipher) {
                                return cipher;
                            } else {
                                return null;
                            }
                        })
                .filter(Objects::nonNull)
                .findFirst();
    }
}
