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
package com.ibm.engine.serializer;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import com.ibm.engine.detection.MethodMatcher;
import java.io.IOException;

public final class MethodMatcherSerializer extends StdSerializer<MethodMatcher> {

    public MethodMatcherSerializer() {
        this(null);
    }

    public MethodMatcherSerializer(Class<MethodMatcher> matcher) {
        super(matcher);
    }

    @Override
    public void serialize(MethodMatcher matcher, JsonGenerator jgen, SerializerProvider provider)
            throws IOException, JsonProcessingException {

        jgen.writeStartObject();

        jgen.writeFieldName("invokedObjectTypeStrings");
        jgen.writeStartArray();
        for (Object e : matcher.getInvokedObjectTypeStringsSerializable()) {
            jgen.writeString((String) e);
        }
        jgen.writeEndArray();

        jgen.writeFieldName("methodNames");
        jgen.writeStartArray();
        for (Object e : matcher.getMethodNamesSerializable()) {
            jgen.writeString((String) e);
        }
        jgen.writeEndArray();

        jgen.writeFieldName("parameterTypes");
        jgen.writeStartArray();
        for (Object e : matcher.getParameterTypesSerializable()) {
            jgen.writeString((String) e);
        }
        jgen.writeEndArray();

        jgen.writeEndObject();
    }
}
