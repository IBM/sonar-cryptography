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

import com.ibm.mapper.model.Version;
import com.ibm.mapper.model.protocl.TLS;
import com.ibm.mapper.utils.DetectionLocation;
import com.ibm.output.cyclondx.CBOMOutputFile;
import org.cyclonedx.model.Bom;
import org.cyclonedx.model.component.crypto.CryptoProperties;
import org.cyclonedx.model.component.crypto.enums.ProtocolType;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ProtocolTest {

    @Test
    void base() {
        DetectionLocation detectionLocation =
                new DetectionLocation("test.java", 1, 1, Collections.emptyList());

        final CBOMOutputFile outputFile = new CBOMOutputFile();

        final TLS tlsProtocol = new TLS(new Version("1.3", detectionLocation));

        outputFile.add(List.of(tlsProtocol));

        final Bom bom = outputFile.getBom();
        assertThat(bom.getComponents()).hasSize(1);
        assertThat(bom.getComponents())
                .anyMatch(
                        component -> {
                            CryptoProperties c = component.getCryptoProperties();
                            return component.getName().equals("TLSv1.3")
                                    && c.getProtocolProperties().getType().equals(ProtocolType.TLS)
                                    && c.getProtocolProperties().getVersion().equals("1.3");
                        });
    }
}
