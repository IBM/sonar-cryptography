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
package com.ibm.rules;

import com.ibm.engine.rule.IBundle;
import com.ibm.mapper.utils.DetectionLocation;
import java.util.Collections;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class TestBase {
    private static final Logger LOGGER = LoggerFactory.getLogger(TestBase.class);

    protected final String filePath = "test.java";
    protected final int lineNumber = 1;
    protected final int offset = 1;
    protected final IBundle bundle = () -> "Test";
    protected final DetectionLocation detectionLocation =
            new DetectionLocation(filePath, lineNumber, offset, Collections.emptyList(), bundle);
}
