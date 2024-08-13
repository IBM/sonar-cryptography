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
import com.ibm.mapper.model.Signature;
import com.ibm.mapper.model.algorithms.RSA;
import org.jetbrains.annotations.NotNull;

public class RSAEnricher implements IEnricher, IEnrichWithDefaultKeySize {

    @NotNull @Override
    public INode enrich(@NotNull INode node) {
        if (node instanceof RSA rsa) {
            if (rsa.is(Signature.class)) {
                return enrichSignature(rsa);
            }
            return enrich(rsa);
        }
        return node;
    }

    @NotNull private RSA enrich(@NotNull RSA rsa) {
        this.applyDefaultKeySizeForJca(rsa, 2048);
        return rsa;
    }

    @NotNull private RSA enrichSignature(@NotNull RSA rsa) {
        return rsa;
    }
}
