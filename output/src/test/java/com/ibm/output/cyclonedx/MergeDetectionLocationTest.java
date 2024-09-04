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

import com.ibm.mapper.model.algorithms.RSA;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Collections;
import java.util.List;
import org.cyclonedx.model.Component;
import org.cyclonedx.model.component.crypto.CryptoProperties;
import org.cyclonedx.model.component.crypto.enums.AssetType;
import org.cyclonedx.model.component.evidence.Occurrence;
import org.junit.jupiter.api.Test;

class MergeDetectionLocationTest extends TestBase {

    @Test
    void differentContexts() {
        this.assertsNodes(
                () -> {
                    DetectionLocation detectionLocation2 =
                            new DetectionLocation(
                                    "test2.java", 2, 2, Collections.emptyList(), () -> "SSL");
                    return List.of(new RSA(detectionLocation), new RSA(detectionLocation2));
                },
                bom -> {
                    assertThat(bom.getComponents()).hasSize(1);
                    Component component = bom.getComponents().get(0);
                    assertThat(component.getName()).isEqualTo("RSA");

                    CryptoProperties cryptoProperties = component.getCryptoProperties();
                    assertThat(cryptoProperties.getAssetType()).isEqualTo(AssetType.ALGORITHM);

                    assertThat(component.getEvidence().getOccurrences()).hasSize(2);
                    assertThat(
                                    component.getEvidence().getOccurrences().stream()
                                            .map(Occurrence::getLocation))
                            .contains("test.java", "test2.java");
                });
    }

    @Test
    void sameContexts() {
        this.assertsNodes(
                () -> List.of(new RSA(detectionLocation), new RSA(detectionLocation)),
                bom -> {
                    assertThat(bom.getComponents()).hasSize(1);
                    Component component = bom.getComponents().get(0);
                    assertThat(component.getName()).isEqualTo("RSA");

                    CryptoProperties cryptoProperties = component.getCryptoProperties();
                    assertThat(cryptoProperties.getAssetType()).isEqualTo(AssetType.ALGORITHM);

                    assertThat(component.getEvidence().getOccurrences()).hasSize(1);
                    assertThat(component.getEvidence().getOccurrences().get(0).getLocation())
                            .isEqualTo("test.java");
                });
    }
}
