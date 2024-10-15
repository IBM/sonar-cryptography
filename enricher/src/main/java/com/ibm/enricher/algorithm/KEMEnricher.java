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
package com.ibm.enricher.algorithm;

import com.ibm.enricher.IEnricher;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.ParameterSetIdentifier;
import com.ibm.mapper.model.algorithms.kyber.MLKEM;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Optional;
import javax.annotation.Nonnull;

public class KEMEnricher implements IEnricher {

    @Override
    public @Nonnull INode enrich(@Nonnull INode node) {
        if (node instanceof MLKEM mlkem) {
            return enrichMLKEM(mlkem);
        }
        return node;
    }

    @Nonnull
    private MLKEM enrichMLKEM(@Nonnull MLKEM mlkem) {
        final Optional<INode> parameterSetIdentifierOptional =
                mlkem.hasChildOfType(ParameterSetIdentifier.class);
        if (parameterSetIdentifierOptional.isPresent()
                && parameterSetIdentifierOptional.get()
                        instanceof ParameterSetIdentifier parameterSetIdentifier) {
            final DetectionLocation detectionLocation =
                    parameterSetIdentifier.getDetectionContext();
            switch (parameterSetIdentifier.asString()) {
                case "512" -> mlkem.put(new Oid("2.16.840.1.101.3.4.4.1", detectionLocation));
                case "768" -> mlkem.put(new Oid("2.16.840.1.101.3.4.4.2", detectionLocation));
                case "1024" -> mlkem.put(new Oid("2.16.840.1.101.3.4.4.3", detectionLocation));
                default -> // the base OID for NIST KEM
                        mlkem.put(new Oid("2.16.840.1.101.3.4.4", detectionLocation));
            }
        }
        return mlkem;
    }
}
