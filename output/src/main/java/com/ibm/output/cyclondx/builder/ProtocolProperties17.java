/*
 * Sonar Cryptography Plugin
 * Copyright (C) 2024 PQCA
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
package com.ibm.output.cyclondx.builder;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import org.cyclonedx.model.component.crypto.ProtocolProperties;
import org.cyclonedx.model.component.crypto.RelatedCryptoMaterialProperties;

public class ProtocolProperties17 extends ProtocolProperties {

    private List<RelatedCryptoMaterialProperties> relatedCryptographicAssets;

    @JsonIgnore
    @Override
    public List<String> getCryptoRefArray() {
        return null;
    }

    @JsonIgnore
    @Override
    public void setCryptoRefArray(List<String> cryptoRefArray) {
        // deprecated in CycloneDX 1.7
    }

    @JsonProperty("relatedCryptographicAssets")
    public List<RelatedCryptoMaterialProperties> getRelatedCryptographicAssets() {
        return relatedCryptographicAssets;
    }

    public void setRelatedCryptographicAssets(
            List<RelatedCryptoMaterialProperties> relatedCryptographicAssets) {
        this.relatedCryptographicAssets = relatedCryptographicAssets;
    }
}
