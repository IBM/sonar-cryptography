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
package com.ibm.plugin.translation.contexts;

import com.ibm.engine.model.CipherAction;
import com.ibm.engine.model.IValue;
import com.ibm.engine.model.context.DigestContext;
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.MessageDigest;
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
            @Nonnull DigestContext.Kind kind,
            @Nonnull DetectionLocation detectionLocation) {
        if (value instanceof CipherAction<Tree> cipherAction) {
            return translateDigestContextCipherAction(cipherAction, kind, detectionLocation);
        }

        return Optional.empty();
    }

    @Nonnull
    private static Optional<INode> translateDigestContextCipherAction(
            @Nonnull final CipherAction<Tree> cipherAction,
            @Nonnull DigestContext.Kind kind,
            @Nonnull DetectionLocation detectionLocation) {
        switch (cipherAction.getAction()) {
            case HASH:
                // No need to switch over kind here
                String hashName =
                        kind.name()
                                .replace(
                                        '_',
                                        '-'); // Python uses "_" (SHA3_384) but the standard way
                // is with "-" (SHA3-384)
                return Optional.of(
                        new MessageDigest(
                                new Algorithm(hashName, detectionLocation), detectionLocation));
            default:
                break;
        }
        return Optional.empty();
    }
}
