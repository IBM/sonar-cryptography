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
package com.ibm.plugin.rules.detection.bc;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Instantiate this class to easily store information related to a cryptographic class name. Using
 * the function {@code putKey} and continuing with other "put" functions, information can be easily
 * stored into an {@code Info} class. The information can then be retrieved using the getter
 * functions of the {@code Info} class, or dedicated helpers like the {@code getDisplayName}
 * function.
 */
public class BouncyCastleInfoMap {

    private final Map<String, Info> map = new ConcurrentHashMap<>();

    public static class Info {
        @Nullable private String name;

        public String getName() {
            return name;
        }

        private void setName(@Nonnull String name) {
            this.name = name;
        }

        @Nullable private String type;

        public String getType() {
            return type;
        }

        private void setType(@Nonnull String type) {
            this.type = type;
        }

        @Nullable private String parameterClass;

        public String getParameterClass() {
            return parameterClass;
        }

        private void setParameterClass(@Nonnull String parameterClass) {
            this.parameterClass = parameterClass;
        }
    }

    public class InfoBuilder {

        private final String key;

        public InfoBuilder(String key) {
            this.key = key;
        }

        private static final String errorMessage = "Unexpected missing key in InfoBuilder: ";

        public InfoBuilder putName(@Nonnull String name) {
            if (!map.containsKey(key)) {
                throw new IllegalArgumentException(errorMessage + key);
            }
            Info info = map.get(key);
            info.setName(name);
            return this;
        }

        public InfoBuilder putType(@Nonnull String type) {
            if (!map.containsKey(key)) {
                throw new IllegalArgumentException(errorMessage + key);
            }
            Info info = map.get(key);
            info.setType(type);
            return this;
        }

        public InfoBuilder putParameterClass(@Nonnull String parameterClass) {
            if (!map.containsKey(key)) {
                throw new IllegalArgumentException(errorMessage + key);
            }
            Info info = map.get(key);
            info.setParameterClass(parameterClass);
            return this;
        }
    }

    /**
     * Add a key to the mapper, and provides additional builder functions to store information like
     * name, type and parameter class.
     *
     * @param key
     * @return An {@code InfoBuilder} object on which can be called some builder functions
     */
    public InfoBuilder putKey(@Nonnull String key) {
        map.computeIfAbsent(key, k -> new Info());
        return new InfoBuilder(key);
    }

    public Set<Entry<String, Info>> entrySet() {
        return map.entrySet();
    }

    /**
     * Returns the correct name of the cryptographic asset. If the asset name was specified with
     * {@code putName}, it will return this name. Otherwise it will return the {@code key}.
     *
     * @param key - Key of the information map, typically the cryptographic class
     * @return The correct name of the cryptographic asset
     */
    public String getDisplayName(@Nonnull String key) {
        return getDisplayName(key, null);
    }

    /**
     * Returns the correct name of the cryptographic asset. If the asset name was specified with
     * {@code putName}, it will return this name. Otherwise it will return the {@code key}, possibly
     * modified by the {@code removePart} argument.
     *
     * @param key - Key of the information map, typically the cryptographic class
     * @param removePart - Substring to remove from the name (only when no specific name was defined
     *     with {@code putName}). If {@code null}, it does nothing.
     * @return The correct name of the cryptographic asset
     */
    public String getDisplayName(@Nonnull String key, String removePart) {
        if (!map.containsKey(key)) {
            throw new IllegalArgumentException("Key does not exist in the map: " + key);
        }

        Info info = map.get(key);

        if (info.getName() != null) {
            return info.getName();
        } else {
            if (removePart == null) {
                return key;
            } else {
                return key.replace(removePart, "");
            }
        }
    }
}
