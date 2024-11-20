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
package com.ibm.plugin;

import java.util.List;
import javax.annotation.Nonnull;
import org.sonar.plugins.java.api.CheckRegistrar;
import org.sonar.plugins.java.api.JavaCheck;
import org.sonarsource.api.sonarlint.SonarLintSide;

@SonarLintSide
public class JavaCheckRegistrar implements CheckRegistrar {

    @Override
    public void register(RegistrarContext registrarContext) {
        // Call to registerClassesForRepository to associate the classes with the correct repository
        registrarContext.registerClassesForRepository(
                JavaScannerRuleDefinition.REPOSITORY_KEY, checkClasses(), testCheckClasses());
    }

    /** Lists all the main checks provided by the java-translation */
    public static @Nonnull List<Class<? extends JavaCheck>> checkClasses() {
        return JavaRuleList.getJavaChecks();
    }

    /** Lists all the test checks provided by the java-translation */
    public static @Nonnull List<Class<? extends JavaCheck>> testCheckClasses() {
        return JavaRuleList.getJavaTestChecks();
    }
}
