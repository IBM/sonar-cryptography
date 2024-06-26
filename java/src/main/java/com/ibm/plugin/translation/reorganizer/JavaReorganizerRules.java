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
package com.ibm.plugin.translation.reorganizer;

import com.ibm.mapper.reorganizer.IReorganizerRule;
import com.ibm.plugin.translation.reorganizer.rules.AeadBlockCipherReorganizer;
import com.ibm.plugin.translation.reorganizer.rules.AsymmetricBlockCipherReorganizer;
import com.ibm.plugin.translation.reorganizer.rules.BlockCipherReorganizer;
import com.ibm.plugin.translation.reorganizer.rules.CipherParameterReorganizer;
import com.ibm.plugin.translation.reorganizer.rules.MacReorganizer;
import com.ibm.plugin.translation.reorganizer.rules.SignerReorganizer;
import java.util.List;
import java.util.stream.Stream;
import javax.annotation.Nonnull;

public final class JavaReorganizerRules {
    private JavaReorganizerRules() {
        // private
    }

    @Nonnull
    public static List<IReorganizerRule> rules() {
        return Stream.of(
                        AeadBlockCipherReorganizer.rules().stream(),
                        AsymmetricBlockCipherReorganizer.rules().stream(),
                        BlockCipherReorganizer.rules().stream(),
                        CipherParameterReorganizer.rules().stream(),
                        MacReorganizer.rules().stream(),
                        SignerReorganizer.rules().stream())
                .flatMap(i -> i)
                .toList();
    }
}
