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

import com.ibm.mapper.model.CipherSuite;
import com.ibm.mapper.model.Identifier;
import com.ibm.mapper.model.KeyAgreement;
import com.ibm.mapper.model.Version;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.algorithms.DH;
import com.ibm.mapper.model.algorithms.DSA;
import com.ibm.mapper.model.algorithms.SHA2;
import com.ibm.mapper.model.collections.AssetCollection;
import com.ibm.mapper.model.collections.IdentifierCollection;
import com.ibm.mapper.model.mode.CBC;
import com.ibm.mapper.model.protocol.TLS;
import java.util.List;
import org.cyclonedx.model.component.crypto.CryptoProperties;
import org.cyclonedx.model.component.crypto.enums.ProtocolType;
import org.junit.jupiter.api.Test;

class ProtocolTest extends TestBase {

    @Test
    void base() {
        this.assertsNode(
                () -> new TLS(new Version("1.3", detectionLocation)),
                bom -> {
                    assertThat(bom.getComponents()).hasSize(1);
                    assertThat(bom.getComponents())
                            .anyMatch(
                                    component -> {
                                        asserts(component.getEvidence());
                                        CryptoProperties c = component.getCryptoProperties();
                                        return component.getName().equals("TLSv1.3")
                                                && c.getProtocolProperties()
                                                        .getType()
                                                        .equals(ProtocolType.TLS)
                                                && c.getProtocolProperties()
                                                        .getVersion()
                                                        .equals("1.3");
                                    });
                });
    }

    @Test
    void cipherSuite() {
        this.assertsNode(
                () -> {
                    final CipherSuite cipherSuite =
                            new CipherSuite(
                                    "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", detectionLocation);
                    final DH dh = new DH(KeyAgreement.class, detectionLocation);
                    final AES aes = new AES(256, new CBC(detectionLocation), detectionLocation);
                    final DSA dsa = new DSA(new SHA2(256, detectionLocation));
                    final AssetCollection assetCollection =
                            new AssetCollection(List.of(dh, aes, dsa));
                    final IdentifierCollection identifierCollection =
                            new IdentifierCollection(
                                    List.of(
                                            new Identifier("0x00", detectionLocation),
                                            new Identifier("0x6A", detectionLocation)));
                    cipherSuite.put(assetCollection);
                    cipherSuite.put(identifierCollection);
                    return cipherSuite;
                },
                bom -> {});
    }
}
