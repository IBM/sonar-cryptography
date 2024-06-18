# Extending the Sonar Cryptography Plugin to add support for another language or cryptography library

The Sonar Cryptography Plugin is designed with a modular architecture so that it can be extended to support additional programming languages and cryptography libraries.

## Introduction to the project structure

The Sonar Cryptography Plugin uses a rule-based approach to precisely identify which cryptography assets are used in the scanned code.
Adding support for detecting a cryptography library means writing a set of rules covering all cryptographic assets introduced by the library.

Defining those rules as part of a SonarQube plugin allows us to easily integrate with usual SonarQube workflows, and to benefit from existing support to scan some languages (languages supported for SonarQube plugins are listed [here](https://docs.sonarsource.com/sonarqube/latest/extension-guide/adding-coding-rules/#custom-rule-support-by-language) in the *Java* column).

### Overview

The project is composed of the following modules:
- The plugin: `sonar-cryptography-plugin`
- One package per supported language, like `java` and `python`
- The detection engine: `engine`
- Four other modules: `mapper`, `enricher`, `output` and `common`

### The plugin

This module ([`sonar-cryptography-plugin`](../sonar-cryptography-plugin/)) is the only SonarQube plugin, for all supported languages, so that we have a single cryptography plugin (and not one per language). 

Its main class is [`CryptoPlugin`](../sonar-cryptography-plugin/src/main/java/com/ibm/plugin/CryptoPlugin.java) which implements the Sonar [`Plugin`](https://javadocs.sonarsource.org/10.3.0.1951/org/sonar/api/Plugin.html) interface, and registers all rules for all languages.
This is done through the `addExtensions` method, and the extension classes to add vary depending on the language (they are usually mentioned in the documentation, or at least appear – in the class implementing `Plugin` – in the example plugins provided by Sonar).

This module also defines the choice of output format for all the findings (in [`OutputFileJob`](../sonar-cryptography-plugin/src/main/java/com/ibm/plugin/OutputFileJob.java)).
Indeed, while any SonarQube plugin will natively report the detected cryptographic findings to the SonarQube instance, our plugin adds an output layer capable of exporting the results in any other format.
These output formats can be defined in the `output` module (with the [`IOutputFileFactory`](../output/src/main/java/com/ibm/output/IOutputFile.java) interface).
Currently, our plugin exports the findings in the standard [CBOM](https://cyclonedx.org/capabilities/cbom/) format.

Ultimately, the `sonar-cryptography-plugin` is the entry point of our SonarQube plugin, it is a lightweight class that does not contain much logic but instead relies on the following modules.


### The language modules

To write detection rules based on the content of the source code, we use an intermediary representation of the source code that is more easy to navigate than plain text: an [AST](https://en.wikipedia.org/wiki/Abstract_syntax_tree) (abstract syntax tree).
The conversion from plain source code to AST is done by a language-specific analyzer, that is provided by SonarQube for languages supported for SonarQube plugins.

Therefore, SonarQube provides us with an API to navigate the source code and determine, for example, if some term is a function or a variable.
Because each programming language has its own syntax, these ASTs (and associated APIs) are language specific too.

Because of this strong language dependency, we use different modules (like `java` and `python`) to separate our rules based on their programming language

#### The detection rules

A language module, like [`java`](../java/), has two main source folders: `rules` and `translation`. Let's first focus on [`rules`](../java/src/main/java/com/ibm/plugin/rules/).

This folder contains all detection rules for the language, organized by cryptography library. For example, the subfolder [`bc`](../java/src/main/java/com/ibm/plugin/rules/detection/bc/) contains all rules related to the BouncyCastle cryptography library, themselves organized based on the structure of this library.

Each rule defines a pattern of the AST corresponding to a function call related to cryptography, and defines the values of interest that should be captured (such as the algorithm name, mode, padding, ...) and included in the output file (typically in the CBOM).
Additionally, dependencies between rules can be specified to captured more complex cryptographic schemes involving multiple functions.

Because all these detection rules follow a similar structure, our goal was to make their writing as easy and short as possible, with a simple and language-agnostic higher level syntax.
Indeed, defining rules directly using the AST APIs would be very verbose, with a lot of duplicated code to perform similar actions, and consequently hard to read.
This higher level syntax is defined by the interface [`IDetectionRule`](../engine/src/main/java/com/ibm/engine/rule/IDetectionRule.java).

> [!TIP]  
> We explain with much more details this higher level syntax for writing detection rules in [*Writing new detection rules for the Sonar Cryptography Plugin*](./DETECTION_RULE_STRUCTURE.md).

Of course, we don't get this nice syntax for free: something has to bridge the gap between the language-specific AST APIs and our language-agnostic syntax.
This is the role of the `engine` module, that will be detailed later.

#### The translation

Writing a detection rule allows us to capture all the values linked to a cryptography asset, for example the name of the algorithm and its mode.
These values are captured in a tree structure shaped like the tree of depending detection rules that detected them, so the tree relationships do not carry any semantic about how the cryptographic values relate to one another.

What we want instead is a meaningful representation of all cryptography related values: a tree structure where relationships between nodes carry some meaning.
Back to our example, we want a tree where the mode is a child node of the algorithm node, to indicate that it's the mode of this algorithm.

This process of building a meaningful tree representation of the captured cryptography values is called the translation. This process is also part of the language module. In certain cases where translation requires to parse a string, the parsing and translation process is outsourced to the `mapper` module for better modularity.

The last step of the translation process is called the enrichment, and is done by the `enricher` module.
This step aims at adding content to the translated tree, based on external knowledge (i.e. not based on the values we captured in the source code).
Indeed, we can get additional information from the documentation of a cryptography library, like some default values.
Maybe our algorithm has a default mode when no mode is specified in the code, in such case we can "enrich" the translated tree with this default mode.
Additionally, we can enrich most cryptography assets with an [object identifier](https://en.wikipedia.org/wiki/Object_identifier) (OID) that uniquely identifies an algorithm and plays an important role in a CBOM.

> [!TIP]  
> The process of translation is also explained with more details in [*Writing new detection rules for the Sonar Cryptography Plugin*](./DETECTION_RULE_STRUCTURE.md).


### The engine

The [`engine`](../engine/) module bridges the gap between the language-specific sonar APIs used for navigating the AST, and the high level language-agnostic API used for writing detection rules.
It has a [`language`](../engine/src/main/java/com/ibm/engine/language/) subfolder which contains the set of functions to implement to enable this high level API for a language supported for SonarQube plugins.

Here are all the interfaces that have to be implemented (specific details about the functions to implement may be documented in the interface files):

- [`IBaseMethodVisitor`](../engine/src/main/java/com/ibm/engine/detection/IBaseMethodVisitor.java) (the class implementing this interface must also extend a language-specific `BaseTreeVisitor` from the sonar API)
- [`IDetectionEngine`](../engine/src/main/java/com/ibm/engine/detection/IDetectionEngine.java)
- [`ILanguageSupport`](../engine/src/main/java/com/ibm/engine/language/ILanguageSupport.java)
- [`ILanguageTranslation`](../engine/src/main/java/com/ibm/engine/language/ILanguageTranslation.java)
- [`IScanContext`](../engine/src/main/java/com/ibm/engine/language/IScanContext.java)

The `engine` module contains a lot of other subfolders and files that enable strong detection capabilities, but they are all based on the functions provided by the `language` files and therefore do not need to be modified when adding support for another file.


## Adding support for another programming language

In this section, we detail step-by-step instructions about how to extend the Sonar Cryptography Plugin to support another language.
Once the plugin supports the targeted language, the next section will detail how to add support for a cryptography library.

Recall that only languages supported for SonarQube plugins are supported (they are listed [here](https://docs.sonarsource.com/sonarqube/latest/extension-guide/adding-coding-rules/#custom-rule-support-by-language) in the *Java* column), because they come with a sonar analyzer and API.

> [!NOTE]  
> If you really want to add support for a language that is not supported for SonarQube plugins, it may be possible to use a third-party analyzer and integrate with SonarQube using [generic formatted issue reports](https://docs.sonarsource.com/sonarqube/latest/analyzing-source-code/importing-external-issues/generic-issue-import-format/).
> However, this has not been attempted yet and will probably result in significantly more work.

In the following, we will take the example of adding support for the Java language.

### Add the language analyzer

The first step is to add a dependency for your sonar language analyzer to the main `sonar-cryptography` [`pom.xml`](../pom.xml).
You should find information about the analyzer group and artifact identifiers in the appropriate language page of the [documentation of sonar languages](https://docs.sonarsource.com/sonarqube/latest/analyzing-source-code/languages/overview/).

Then, first add its version under `<!-- language parser versions -->`:
```xml
<sonar.java.version>7.35.0.36271</sonar.java.version>
```

And add the dependency (using this version reference) under `<!-- language supporters -->`:
```xml
<dependency>
    <groupId>org.sonarsource.java</groupId>
    <artifactId>sonar-java-plugin</artifactId>
    <version>${sonar.java.version}</version>
</dependency>
```

### Creating a new language module

Now that the language analyzer has been registered in the main `pom.xml`, we can create a new module named like the language (like [`java`](../java/)).

> [!IMPORTANT]  
> This process depends on how the language analyzer APIs work: **carefully read the available documentation explaining how to create a SonarQube plugin for your language first**. This documentation should take precedence over the more general explanations that we will discuss next.
> 
> The documentation may come with a sample plugin for your language, in this case it will help you to have a look at it to understand how your plugin can integrate with SonarQube.

The first step is to create another [`pom.xml`](../java/pom.xml) for your new module.
Take inspiration from the `pom.xml` of the existing language modules to write it.
In short, it should contain a reference to the parent `sonar-cryptography`, maven properties, dependencies to the other modules that will be used (typically `common`, `output` and `enricher`), and a dependency to the language-specific sonar test kit.

Then, fill your module folder with the same basic structure as the other language modules. For example for java:
```
java
└── src
    ├── main/java/com/ibm/plugin
    │   ├── rules
    │   │   └── detection
    │   └── translation
    └── test
        ├── files/rules
        └── java/com/ibm/plugin/rules
```

`plugin/rules` will contain the detection rules, organized by cryptography library, and `plugin/translation` will contain all files related to translation for this language.

Then, we have to add *extension points*: these are language-specific interfaces to implement in order to declare the custom detection rules of the module to the plugin. Read the sonar documentation to find what these interfaces are. For Java, these are the interfaces `RulesDefinition` and `CheckRegistrar`, respectively implemented in [`JavaScannerRuleDefinition`](../java/src/main/java/com/ibm/plugin/JavaScannerRuleDefinition.java) and [`JavaCheckRegistrar`](../java/src/main/java/com/ibm/plugin/JavaCheckRegistrar.java) in the `plugin` directory.

> [!IMPORTANT]  
> At this point, we have to clarify an important difference: we distinguish the SonarQube *rules* that we actually add to the plugin, and the detection *rules* (defined [earlier](#the-detection-rules)) that are rules written with our high level syntax and conforming to the `IDetectionRule` interface.
>
> In our plugin architecture, we make the choice to define a **single** SonarQube rule per language, that contains the logic of all detection rules. This rule conforms to a language-specific interface defined by your sonar analyzer API, like `IssuableSubscriptionVisitor` in Java or `PythonVisitorCheck` in Python.
>
> This means that on the SonarQube UI, we see only one (meaningless) rule that reports any kind of cryptography finding. The actual precise information should instead be exported through the `output` module, like we currently do with the CBOM. 

We now explain with a bit more detail what the usual extension points are.

#### Check Registrar

If there is a similar entry point for your language, you can set it up similarly to Java (or to [`PythonCheckRegistrar`](../python/src/main/java/com/ibm/plugin/PythonCheckRegistrar.java) with the `PythonCustomRuleRepository` interface).

This is the place where the SonarQube rule class should be referenced. Because this rule "regroups" all the detection rule, we call it the *inventory rule*, which is defined in Java as [`JavaInventoryRule`](../java/src/main/java/com/ibm/plugin/rules/JavaInventoryRule.java) in `plugin/rules`.

This rule must implement the language-specific sonar rule interface, `IssuableSubscriptionVisitor` in Java, and must be annotated with a name:
```java
@Rule(key = "Inventory")
```

We define the logic behind the inventory rule (and in particular how it will relate with all the `IDetectionRule` detection rules) in the `plugin/rules/detection` directory by creating an intermediary class implementing the language-specific sonar rule interface (`IssuableSubscriptionVisitor` in Java) and from which the inventory rule (`JavaInventoryRule`) will inherit. In Java, we call this class [`JavaBaseDetectionRule`](../java/src/main/java/com/ibm/plugin/rules/detection/JavaBaseDetectionRule.java) and it takes a constructor with a list of `IDetectionRule`[^1]. 

[^1]: It may also take a list of [`IReorganizerRule`](../mapper/src/main/java/com/ibm/mapper/reorganizer/IReorganizerRule.java) if necessary. More about this in [*Writing new detection rules for the Sonar Cryptography Plugin*](./DETECTION_RULE_STRUCTURE.md)




#### Rule Definition

If there is a similar entry point for your language, you can set it up similarly to Java (or Python) by providing basic metadata information about this rule that will be displayed in the SonarQube UI.





<br><br><br><br><br><br><br><br><br><br>
---

- Update the POM.xml
- Create a new language module (get inspired by a template plugin), find and integrate the extension points:
https://docs.sonarsource.com/sonarqube/latest/analyzing-source-code/languages/overview/
    - register it in the main POM.xml
    - Write the basic architecture of the language module
- Create a new language subfolder and integrate with the engine
- Add this language in the plugin module where needed

## Adding support for another cryptography library

- Create library-specific folders
- Write rules and associated test files (TDD) [delegate to other markdown file]