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

import com.ibm.engine.model.CipherAction;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.KeySize;
import com.ibm.engine.model.ValueAction;
import com.ibm.engine.model.context.CipherContext;
import com.ibm.mapper.mapper.pyca.PycaCipherMapper;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.KeyLength;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.functionality.Decrypt;
import com.ibm.mapper.model.functionality.Encapsulate;
import com.ibm.mapper.model.functionality.Encrypt;
import com.ibm.mapper.model.mode.CCM;
import com.ibm.mapper.model.mode.GCM;
import com.ibm.mapper.model.mode.GCMSIV;
import com.ibm.mapper.model.mode.OCB;
import com.ibm.mapper.model.mode.SIV;
import com.ibm.mapper.model.padding.ANSIX923;
import com.ibm.mapper.model.padding.OAEP;
import com.ibm.mapper.model.padding.PKCS7;
import com.ibm.mapper.utils.DetectionLocation;
import org.sonar.plugins.python.api.tree.Tree;

import javax.annotation.Nonnull;
import java.util.Optional;

@SuppressWarnings("java:S1301")
public final class PythonCipherContextTranslator {

    private PythonCipherContextTranslator() {
        // private static
    }

    @Nonnull
    public static Optional<INode> translateForCipherContext(
            @Nonnull final IValue<Tree> value,
            @Nonnull CipherContext context,
            @Nonnull DetectionLocation detectionLocation) {
        final PycaCipherMapper pycaCipherMapper = new PycaCipherMapper();

        if (value instanceof com.ibm.engine.model.Algorithm<Tree>) {
            if (context.get("kind").map(k -> k.equals("AEAD")).orElse(false)) {
                return switch (value.asString().toUpperCase().trim()) {
                    case "AESGCM" ->
                            Optional.of(new AES(new GCM(detectionLocation), detectionLocation));
                    case "AESGCMIV" ->
                            Optional.of(new AES(new GCMSIV(detectionLocation), detectionLocation));
                    case "AESOCB3" ->
                            Optional.of(new AES(new OCB(3, detectionLocation), detectionLocation));
                    case "AESSIV" ->
                            Optional.of(new AES(new SIV(detectionLocation), detectionLocation));
                    case "AESCCM" ->
                            Optional.of(new AES(new CCM(detectionLocation), detectionLocation));
                    default -> Optional.empty();
                };
            }
            return pycaCipherMapper.parse(value.asString(), detectionLocation).map(i -> i);
        } else if (value instanceof ValueAction<Tree>
                && context.get("kind").map(k -> k.equals("padding")).orElse(false) // padding case
        ) {
            return switch (value.asString().toUpperCase().trim()) {
                case "PKCS7" -> Optional.of(new PKCS7(detectionLocation));
                case "ANSIX923" -> Optional.of(new ANSIX923(detectionLocation));
                case "OAEP" -> Optional.of(new OAEP(detectionLocation));
                default -> Optional.empty();
            };
        } else if (value instanceof CipherAction<Tree> cipherAction) {
            final Optional<String> algorithmStr = context.get("algorithm");
            if (algorithmStr.isPresent()) {
                return pycaCipherMapper
                        .parse(algorithmStr.get(), detectionLocation)
                        .map(
                                algo -> {
                                    switch (cipherAction.getAction()) {
                                        case DECRYPT -> algo.put(new Decrypt(detectionLocation));
                                        case ENCRYPT -> algo.put(new Encrypt(detectionLocation));
                                        case WRAP -> algo.put(new Encapsulate(detectionLocation));
                                        default -> {
                                            // nothing
                                        }
                                    }
                                    return algo;
                                });
            }
        } else if (value instanceof com.ibm.engine.model.BlockSize<Tree> blockSize) {
            return Optional.of(new BlockSize(blockSize.getValue(), detectionLocation));
        } else if (value instanceof KeySize<Tree> keySize) {
            return Optional.of(new KeyLength(keySize.getValue(), detectionLocation));
        }
        return Optional.empty();
    }
}
