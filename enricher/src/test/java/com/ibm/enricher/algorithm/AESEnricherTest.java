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
import com.ibm.mapper.model.AuthenticatedEncryption;
import com.ibm.mapper.model.BlockSize;
import com.ibm.mapper.model.DigestSize;
import com.ibm.mapper.model.INode;
import com.ibm.mapper.model.Oid;
import com.ibm.mapper.model.algorithms.AES;
import com.ibm.mapper.model.mode.GCM;
import com.ibm.mapper.model.padding.PKCS1;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.List;
import org.junit.jupiter.api.Test;

class AESEnricherTest extends TestBase {

    @Test
    void ae() {
        DetectionLocation testDetectionLocation =
                new DetectionLocation("testfile", 1, 1, List.of("test"));
        final AES aes = new AES(testDetectionLocation);
        aes.append(new DigestSize(128, testDetectionLocation));
        aes.append(new GCM(testDetectionLocation));
        aes.append(new PKCS1(testDetectionLocation));
        this.logBefore(aes);

        final AESEnricher aesEnricher = new AESEnricher();
        final INode enriched = aesEnricher.enrich(aes);
        this.logAfter(enriched);

        assertThat(enriched.is(AuthenticatedEncryption.class)).isTrue();
        assertThat(enriched).isInstanceOf(AES.class);
        final AES enrichedAES = (AES) enriched;

        assertThat(enrichedAES.hasChildOfType(BlockSize.class)).isPresent();
        assertThat(enrichedAES.hasChildOfType(Oid.class)).isPresent();

        assertThat(enrichedAES.hasChildOfType(BlockSize.class).get().asString()).isEqualTo("128");
        assertThat(enrichedAES.hasChildOfType(Oid.class).get().asString())
                .isEqualTo("2.16.840.1.101.3.4.1.6");
    }
}
