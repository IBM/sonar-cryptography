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
package com.ibm.enricher;

import com.ibm.enricher.algorithm.AlgorithmEnricher;
import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.INode;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;

public class Enricher implements IEnricher {

    public static void enrich(@Nonnull final List<INode> nodes) {
        final Enricher enricher = new Enricher();
        nodes.forEach(enricher::enrich);
        nodes.forEach(
                v -> {
                    if (v.hasChildren()) {
                        enrich(v.getChildren().values().stream().toList());
                    }
                });
    }

    @Override
    public void enrich(@Nonnull INode node) {
        if (node instanceof Algorithm algorithm) {
            final AlgorithmEnricher algorithmEnricher = new AlgorithmEnricher();
            algorithmEnricher.enrich(algorithm, Map.of());
        }
    }
}
