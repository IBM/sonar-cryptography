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
package com.ibm.mapper.model;

import com.ibm.mapper.configuration.Configuration;
import com.ibm.mapper.utils.DetectionLocation;
import javax.annotation.Nonnull;

public class Version extends Property {

    @Nonnull private String value;

    public Version(@Nonnull String value, @Nonnull DetectionLocation detectionLocation) {
        super(Version.class, detectionLocation);
        this.value = value;
    }

    private Version(@Nonnull Version version) {
        super(version.type, version.detectionLocation, version.children);
        this.value = version.value;
    }

    @Nonnull
    public String getValue() {
        return value;
    }

    @Override
    public void apply(@Nonnull Configuration configuration) {
        this.value = configuration.changeStringValue(value);
    }

    @Nonnull
    @Override
    public String asString() {
        return value;
    }

    @Nonnull
    @Override
    public INode deepCopy() {
        Version copy = new Version(this);
        for (INode child : this.children.values()) {
            copy.children.put(child.getKind(), child.deepCopy());
        }
        return copy;
    }

    @Override
    public final boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Version version)) return false;
        if (!super.equals(o)) return false;

        return value.equals(version.value);
    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + value.hashCode();
        return result;
    }
}
