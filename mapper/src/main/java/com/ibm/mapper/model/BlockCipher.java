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

public class BlockCipher extends Cipher {

    public BlockCipher(@Nonnull Algorithm algorithm) {
        super(algorithm, BlockCipher.class);
    }

    public BlockCipher(@Nonnull Algorithm algorithm, @Nonnull Mode mode) {
        super(algorithm, mode, BlockCipher.class);
    }

    public BlockCipher(@Nonnull Algorithm algorithm, @Nonnull Mode mode, @Nonnull Padding padding) {
        super(algorithm, mode, padding, BlockCipher.class);
    }

    protected BlockCipher(
            @Nonnull Algorithm algorithm, @Nonnull final Class<? extends ICipher> asKind) {
        super(algorithm, asKind);
    }
}
