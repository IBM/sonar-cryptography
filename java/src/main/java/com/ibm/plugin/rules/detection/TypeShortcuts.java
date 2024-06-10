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
package com.ibm.plugin.rules.detection;

public final class TypeShortcuts {
    public static final String STRING_TYPE = "java.lang.String";
    public static final String BYTE_ARRAY_TYPE = "byte[]";
    public static final String BIGINTEGER_TYPE = "java.math.BigInteger";
    public static final String CHAR_ARRAY_TYPE = "char[]";
    public static final String CIPHER_TYPE = "javax.crypto.Cipher";
    public static final String KEY_TYPE = "java.security.Key";
    public static final String KEY_SPEC_TYPE = "java.security.spec.KeySpec";

    private TypeShortcuts() {
        // nothing
    }
}
