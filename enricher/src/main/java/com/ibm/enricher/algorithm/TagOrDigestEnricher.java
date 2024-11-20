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
import com.ibm.mapper.model.ExtendableOutputFunction;
import com.ibm.mapper.model.IAsset;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Mac;
import com.ibm.mapper.model.MessageDigest;
import com.ibm.mapper.model.functionality.Digest;
import com.ibm.mapper.model.functionality.Tag;
import javax.annotation.Nonnull;

public class TagOrDigestEnricher implements IEnricher {

    @Override
    public @Nonnull INode enrich(@Nonnull INode node) {
        if (node instanceof IAsset asset) {
            if (node.is(Mac.class)) {
                node.put(new Tag(asset.getDetectionContext()));
                return node;
            } else if (node.is(MessageDigest.class) || node.is(ExtendableOutputFunction.class)) {
                node.put(new Digest(asset.getDetectionContext()));
                return node;
            }
        }
        return node;
    }
}
