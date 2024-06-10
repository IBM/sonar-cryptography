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
package com.ibm.engine.detection;

import com.ibm.engine.language.ILanguageTranslation;
import java.util.Optional;
import java.util.function.Function;
import java.util.function.Predicate;
import javax.annotation.Nonnull;

public final class EnumMatcher<T> {

    @Nonnull private final Predicate<String> enumValueIdentifierName;

    public EnumMatcher(@Nonnull String enumValueIdentifierName) {
        this.enumValueIdentifierName =
                createPredicate(enumValueIdentifierName, (name1 -> (name1::equals)));
    }

    private static <E> Predicate<E> createPredicate(
            @Nonnull String element,
            @Nonnull Function<String, Predicate<E>> singleElementPredicate) {
        return singleElementPredicate.apply(element);
    }

    public boolean match(
            @Nonnull T enumClass,
            @Nonnull ILanguageTranslation<T> translation,
            @Nonnull MatchContext matchContext) {
        Optional<String> enumClassName = translation.getEnumClassName(matchContext, enumClass);
        return enumClassName.filter(this.enumValueIdentifierName).isPresent();
    }
}
