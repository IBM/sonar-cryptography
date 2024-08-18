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
package com.ibm.plugin.translation.translator.contexts;

import com.ibm.engine.model.IValue;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.algorithms.MD5;
import com.ibm.mapper.model.algorithms.SHA;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.algorithms.SHA3;
import com.ibm.mapper.model.algorithms.SHAKE;
import com.ibm.mapper.model.algorithms.SM3;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;
import org.sonar.plugins.python.api.tree.Tree;

@SuppressWarnings("java:S1301")
public final class PythonDigestContextTranslator {

    private PythonDigestContextTranslator() {
        // private
    }

    @Nonnull
    public static Optional<INode> translateForDigestContext(
            @Nonnull final IValue<Tree> value,
            @Nonnull DigestContext context,
            @Nonnull DetectionLocation detectionLocation) {
        if (value instanceof ValueAction<Tree>) {
            return switch (value.asString().toUpperCase().trim()) {
                case "SHA1" -> Optional.of(new SHA(detectionLocation));
                case "SHA512_224" ->
                        Optional.of(
                                new SHA2(224, new SHA2(512, detectionLocation), detectionLocation));
                case "SHA512_256" ->
                        Optional.of(
                                new SHA2(256, new SHA2(512, detectionLocation), detectionLocation));
                case "SHA224" -> Optional.of(new SHA2(224, detectionLocation));
                case "SHA256" -> Optional.of(new SHA2(256, detectionLocation));
                case "SHA384" -> Optional.of(new SHA2(384, detectionLocation));
                case "SHA512" -> Optional.of(new SHA2(512, detectionLocation));
                case "SHA3_224" -> Optional.of(new SHA3(224, detectionLocation));
                case "SHA3_256" -> Optional.of(new SHA3(256, detectionLocation));
                case "SHA3_384" -> Optional.of(new SHA3(384, detectionLocation));
                case "SHA3_512" -> Optional.of(new SHA3(512, detectionLocation));
                case "SHAKE128" -> Optional.of(new SHAKE(128, detectionLocation));
                case "SHAKE256" -> Optional.of(new SHAKE(256, detectionLocation));
                case "MD5" -> Optional.of(new MD5(detectionLocation));
                case "BLAKE2B" -> Optional.empty(); // TODO
                case "BLAKE2S" -> Optional.empty(); // TODO
                case "SM3" -> Optional.of(new SM3(detectionLocation));
                default -> Optional.empty();
            };
        }
        return Optional.empty();
    }
}
