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

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.enricher.TestBase;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.algorithms.SHA3;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import org.junit.jupiter.api.Test;

class SHA3EnricherTest extends TestBase {

    @Test
    void base() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"), () -> "Jca");
        final SHA3 sha256 = new SHA3(256, testDetectionLocation);
        this.logBefore(sha256);

        final SHA3Enricher sha3Enricher = new SHA3Enricher();
        final INode enriched = sha3Enricher.enrich(sha256);
        this.logAfter(enriched);

        assertThat(enriched.hasChildOfType(Oid.class)).isPresent();
        assertThat(enriched.hasChildOfType(Oid.class).get().asString())
                .isEqualTo("2.16.840.1.101.3.4.2.8");

        assertThat(enriched.hasChildOfType(BlockSize.class)).isPresent();
        assertThat(enriched.hasChildOfType(BlockSize.class).get().asString()).isEqualTo("1088");
    }
}
