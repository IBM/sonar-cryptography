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
import java.io.IOException;
import java.util.Map;
import java.util.Set;

public final class DetectionRuleStoreSerializer extends StdSerializer<DetectionRuleStore> {

    public DetectionRuleStoreSerializer() {
        this(null);
    }

    public DetectionRuleStoreSerializer(Class<DetectionRuleStore> detectionRuleStore) {
        super(detectionRuleStore);
    }

    @Override
    public void serialize(
            DetectionRuleStore detectionRuleStore, JsonGenerator jgen, SerializerProvider provider)
            throws IOException, JsonProcessingException {

        jgen.writeStartObject();

        jgen.writeFieldName("id");
        jgen.writeString(detectionRuleStore.getId());

        jgen.writeFieldName("isEntryPoint");
        jgen.writeBoolean(detectionRuleStore.isEntryPoint());

        jgen.writeFieldName("methodMatcher");
        jgen.writeObject(detectionRuleStore.getMatchers());

        jgen.writeFieldName("parameterNextDetectionRules");
        Map<String, Set<String>> parameterMap =
                (Map<String, Set<String>>) detectionRuleStore.getParameterNextDetectionRules();

        // Start writing the JSON array
        jgen.writeStartArray();

        // Serialize each entry of the map
        for (Map.Entry<String, Set<String>> entry : parameterMap.entrySet()) {
            String key = entry.getKey();
            Set<String> values = entry.getValue();

            // Start writing the JSON object for each entry
            jgen.writeStartObject();

            // Write key
            jgen.writeStringField("key", key);

            // Write values as array
            jgen.writeArrayFieldStart("values");
            for (String value : values) {
                jgen.writeString(value);
            }
            jgen.writeEndArray();

            // End writing the JSON object for each entry
            jgen.writeEndObject();
        }

        // End writing the JSON array
        jgen.writeEndArray();

        jgen.writeFieldName("nextDetectionRules");
        jgen.writeStartArray();
        for (Object e : detectionRuleStore.getNextDetectionRules()) {
            jgen.writeString((String) e);
        }
        jgen.writeEndArray();

        jgen.writeEndObject();
    }
}
