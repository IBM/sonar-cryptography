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
package com.ibm.mapper.model.algorithms;

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.BlockCipher;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.IPrimitive;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;

public class Kalyna extends Algorithm implements BlockCipher, Mac {
    // https://en.wikipedia.org/wiki/Kalyna_(cipher)
    // https://eprint.iacr.org/2015/650.pdf

    private static final String NAME = "Kalyna"; // DSTU 7624:2014

    /**
     * Returns a name of the form "Kalyna-XXX/YYY" where XXX is the block size and YYY is the key
     * length
     */
    @Override
    @Nonnull
    public String getName() {
        StringBuilder builtName = new StringBuilder(this.name);

        Optional<INode> blockSize = this.hasChildOfType(BlockSize.class);
        Optional<INode> keyLength = this.hasChildOfType(KeyLength.class);

        if (blockSize.isPresent() && keyLength.isPresent()) {
            builtName
                    .append("-")
                    .append(blockSize.get().asString())
                    .append("/")
                    .append(keyLength.get().asString());
        }

        return builtName.toString();
    }

    public Kalyna(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, BlockCipher.class, detectionLocation);
    }

    public Kalyna(int blockSize, @Nonnull DetectionLocation detectionLocation) {
        this(detectionLocation);
        this.put(new BlockSize(blockSize, detectionLocation));
    }

    public Kalyna(int blockSize, int keyLength, @Nonnull DetectionLocation detectionLocation) {
        this(detectionLocation);
        this.put(new BlockSize(blockSize, detectionLocation));
        this.put(new KeyLength(keyLength, detectionLocation));
    }

    public Kalyna(@Nonnull final Class<? extends IPrimitive> asKind, @Nonnull Kalyna kalyna) {
        super(kalyna, asKind);
    }
}
