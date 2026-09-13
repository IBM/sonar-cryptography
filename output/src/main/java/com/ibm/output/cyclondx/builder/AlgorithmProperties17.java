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
import org.cyclonedx.model.component.crypto.AlgorithmProperties;

public class AlgorithmProperties17 extends AlgorithmProperties {

    private String algorithmFamily;
    private String ellipticCurve;

    @JsonIgnore
    @Override
    public String getCurve() {
        return null;
    }

    @JsonIgnore
    @Override
    public void setCurve(String curve) {
        // deprecated in CycloneDX 1.7, replaced by ellipticCurve
    }

    @JsonProperty("algorithmFamily")
    public String getAlgorithmFamily() {
        return algorithmFamily;
    }

    public void setAlgorithmFamily(String algorithmFamily) {
        this.algorithmFamily = algorithmFamily;
    }

    @JsonProperty("ellipticCurve")
    public String getEllipticCurve() {
        return ellipticCurve;
    }

    public void setEllipticCurve(String ellipticCurve) {
        this.ellipticCurve = ellipticCurve;
    }
}
