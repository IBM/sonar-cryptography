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
package com.ibm.plugin.translation;

import com.ibm.mapper.configuration.Configuration;
import javax.annotation.Nonnull;

public class PythonMapperConfig extends Configuration {

    // TODO: Is there something to change compared to the Java case in this file?
    @Nonnull
    @Override
    public String changeStringValue(@Nonnull String value) {

        if (value.contains("NoPadding")) {
            return "";
        }

        if (value.contains("Padding")) {
            return value.replace("Padding", "");
        }

        return value;
    }
}
