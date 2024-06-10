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
package com.ibm.output.cyclonedx;

import static org.assertj.core.api.Assertions.assertThat;

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.output.cyclondx.CBOMOutputFile;
import java.util.Collections;
import java.util.List;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.component.crypto.CryptoProperties;
import org.cyclonedx.model.component.crypto.enums.AssetType;
import org.junit.jupiter.api.Test;

class MergeDetectionLocationTest {

    @Test
    void differentContexts() {
        final CBOMOutputFile outputFile = new CBOMOutputFile();
        // asset 1
        DetectionLocation detectionLocation =
                new DetectionLocation("test1.java", 1, 1, Collections.emptyList());
        Algorithm algorithm = new Algorithm("RSA", detectionLocation);
        outputFile.add(List.of(algorithm));
        // asset 2
        detectionLocation = new DetectionLocation("test2.java", 2, 2, Collections.emptyList());
        algorithm = new Algorithm("RSA", detectionLocation);
        outputFile.add(List.of(algorithm));

        final Bom bom = outputFile.getBom();

        assertThat(bom.getComponents()).hasSize(1);
        Component component = bom.getComponents().get(0);
        assertThat(component.getName()).isEqualTo("rsa");

        CryptoProperties cryptoProperties = component.getCryptoProperties();
        assertThat(cryptoProperties.getAssetType()).isEqualTo(AssetType.ALGORITHM);

        assertThat(component.getEvidence().getOccurrences()).hasSize(2);
        assertThat(component.getEvidence().getOccurrences())
                .anyMatch(o -> o.getLocation().equals("test1.java"));
        assertThat(component.getEvidence().getOccurrences())
                .anyMatch(o -> o.getLocation().equals("test2.java"));
    }

    @Test
    void sameContexts() {
        final CBOMOutputFile outputFile = new CBOMOutputFile();
        // asset 1
        DetectionLocation detectionLocation =
                new DetectionLocation("test1.java", 1, 1, Collections.emptyList());
        Algorithm algorithm = new Algorithm("RSA", detectionLocation);
        outputFile.add(List.of(algorithm));
        // asset 2
        detectionLocation = new DetectionLocation("test1.java", 1, 1, Collections.emptyList());
        algorithm = new Algorithm("RSA", detectionLocation);
        outputFile.add(List.of(algorithm));

        final Bom bom = outputFile.getBom();

        assertThat(bom.getComponents()).hasSize(1);
        Component component = bom.getComponents().get(0);
        assertThat(component.getName()).isEqualTo("rsa");

        CryptoProperties cryptoProperties = component.getCryptoProperties();
        assertThat(cryptoProperties.getAssetType()).isEqualTo(AssetType.ALGORITHM);

        assertThat(component.getEvidence().getOccurrences()).hasSize(1);
        assertThat(component.getEvidence().getOccurrences())
                .anyMatch(o -> o.getLocation().equals("test1.java"));
    }
}
