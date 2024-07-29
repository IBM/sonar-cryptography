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

public class MessageDigest extends Algorithm {
    public MessageDigest(@Nonnull Algorithm algorithm) {
        super(algorithm, MessageDigest.class);
    }

    public MessageDigest(@Nonnull Algorithm algorithm, @Nonnull DigestSize digestSize) {
        super(algorithm, MessageDigest.class);
        this.append(digestSize);
    }

    public MessageDigest(
            @Nonnull Algorithm algorithm,
            @Nonnull DigestSize digestSize,
            @Nonnull BlockSize blockSize) {
        super(algorithm, MessageDigest.class);
        this.append(digestSize);
        this.append(blockSize);
    }

    @Nonnull
    public Optional<DigestSize> getDigestSize() {
        INode node = this.getChildren().get(DigestSize.class);
        if (node == null) {
            return Optional.empty();
        }
        return Optional.of((DigestSize) node);
    }

    @Nonnull
    public Optional<BlockSize> getBlockSize() {
        INode node = this.getChildren().get(BlockSize.class);
        if (node == null) {
            return Optional.empty();
        }
        return Optional.of((BlockSize) node);
    }
}
