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
package com.ibm.mapper.model.algorithms;

import com.ibm.mapper.model.Algorithm;
import com.ibm.mapper.model.KeyWrap;
import com.ibm.mapper.utils.DetectionLocation;
import javax.annotation.Nonnull;

public class RFC3211Wrap extends Algorithm implements KeyWrap {
    // https://datatracker.ietf.org/doc/html/rfc3211#section-2.3.1

    private static final String NAME = "RFC 3211";

    public RFC3211Wrap(@Nonnull DetectionLocation detectionLocation) {
        super(NAME, KeyWrap.class, detectionLocation);
    }
}