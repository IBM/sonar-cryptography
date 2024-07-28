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

import javax.annotation.Nonnull;
import java.util.Optional;

public final class PasswordBasedEncryption extends Algorithm {

    // example: PBEWithHmacSHA1AndAES_128
    public PasswordBasedEncryption(
            @Nonnull HMAC hmac,
            @Nonnull Cipher cipher) {
        super(new Algorithm("PBEWith" + hmac.asString() + "and" + cipher.asString(), hmac.detectionLocation),
                hmac.detectionLocation, PasswordBasedEncryption.class);
        this.append(hmac);
        this.append(cipher);
    }

    // example: PBEWithMD5AndDES
    public PasswordBasedEncryption(
            @Nonnull MessageDigest digest,
            @Nonnull Cipher cipher) {
        super(new Algorithm("PBEWith" + digest.asString() + "and" + cipher.asString(), digest.detectionLocation),
                digest.detectionLocation, PasswordBasedEncryption.class);
        this.append(digest);
        this.append(cipher);
    }

    // example: PBEWithHmacSHA1
    public PasswordBasedEncryption(
            @Nonnull HMAC hmac) {
        super(new Algorithm("PBEWith" + hmac.asString(), hmac.detectionLocation),
                hmac.detectionLocation, PasswordBasedEncryption.class);
        this.append(hmac);
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
        INode node = this.getChildren().get(Cipher.class);
        if (node == null) {
            return Optional.empty();
        }
        return Optional.of((Cipher) node);
    }
}
