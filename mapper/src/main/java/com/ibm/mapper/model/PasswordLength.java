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

import com.ibm.mapper.utils.DetectionLocation;

import javax.annotation.Nonnull;
import java.util.Objects;

public final class PasswordLength extends Property {
    @Nonnull private final Integer value; // in bit

    public PasswordLength(@Nonnull Integer value, @Nonnull DetectionLocation detectionLocation) {
        super(PasswordLength.class, detectionLocation);
        this.value = value;
    }

    private PasswordLength(@Nonnull PasswordLength passwordLength) {
        super(passwordLength.type, passwordLength.detectionLocation, passwordLength.children);
        this.value = passwordLength.value;
    }

    @Nonnull
    public Integer getValue() {
        return value;
    }

    @Nonnull
    @Override
    public String asString() {
        return value.toString();
    }

    @Nonnull
    @Override
    public INode deepCopy() {
        PasswordLength copy = new PasswordLength(this);
        for (INode child : this.children.values()) {
            copy.children.put(child.getKind(), child.deepCopy());
        }
        return copy;
    }

    @Override
    public boolean equals(Object object) {
        if (this == object) return true;
        if (!(object instanceof PasswordLength passwordLength)) return false;
        if (!super.equals(object)) return false;
        return Objects.equals(value, passwordLength.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), value);
    }
}
