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
import org.cyclonedx.model.Hash;
import org.cyclonedx.model.component.crypto.CertificateProperties;

public class CertificateProperties17 extends CertificateProperties {

    private String certificateFileExtension;
    private String serialNumber;
    private Hash fingerprint;
    private List<CertificateExtension17> certificateExtensions;

    @JsonIgnore
    @Override
    public String getCertificateExtension() {
        return null;
    }

    @JsonIgnore
    @Override
    public void setCertificateExtension(String certificateExtension) {
        // deprecated in CycloneDX 1.7, replaced by certificateFileExtension
    }

    @JsonProperty("certificateFileExtension")
    public String getCertificateFileExtension() {
        return certificateFileExtension;
    }

    public void setCertificateFileExtension(String certificateFileExtension) {
        this.certificateFileExtension = certificateFileExtension;
    }

    @JsonProperty("serialNumber")
    public String getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    @JsonProperty("fingerprint")
    public Hash getFingerprint() {
        return fingerprint;
    }

    public void setFingerprint(Hash fingerprint) {
        this.fingerprint = fingerprint;
    }

    @JsonProperty("certificateExtensions")
    public List<CertificateExtension17> getCertificateExtensions() {
        return certificateExtensions;
    }

    public void setCertificateExtensions(List<CertificateExtension17> certificateExtensions) {
        this.certificateExtensions = certificateExtensions;
    }

    public static class CertificateExtension17 {

        private String id;
        private String name;
        private boolean critical;
        private String value;

        @JsonProperty("id")
        public String getId() {
            return id;
        }

        public void setId(String id) {
            this.id = id;
        }

        @JsonProperty("name")
        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        @JsonProperty("critical")
        public boolean isCritical() {
            return critical;
        }

        public void setCritical(boolean critical) {
            this.critical = critical;
        }

        @JsonProperty("value")
        public String getValue() {
            return value;
        }

        public void setValue(String value) {
            this.value = value;
        }
    }
}
