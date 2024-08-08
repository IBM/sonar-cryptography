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
import com.ibm.mapper.model.algorithms.RSAssaPSS;
import org.jetbrains.annotations.NotNull;

public class RSAssaPSSEnricher implements IEnricher {
    @Override
    public @NotNull INode enrich(@NotNull INode node) {
        if (node instanceof RSAssaPSS rsaSsaPSS) {
            rsaSsaPSS.append(new Oid("1.2.840.113549.1.1.10", rsaSsaPSS.getDetectionContext()));
            return rsaSsaPSS;
        }
        return node;
    }
}