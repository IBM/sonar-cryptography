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

Its main file is [`CryptoPlugin.java`](../sonar-cryptography-plugin/src/main/java/com/ibm/plugin/CryptoPlugin.java) which implements the Sonar [`Plugin`](https://javadocs.sonarsource.org/10.3.0.1951/org/sonar/api/Plugin.html) interface, and registers all rules for all languages.
This is done through the `addExtensions` method, and the extension classes to add vary depending on the language (they are usually mentioned in the documentation, or at least appear – in the class implementing `Plugin` – in the example plugins provided by Sonar).

This class also defines the choice of output format for all the findings (in [`OutputFileJob.java`](../sonar-cryptography-plugin/src/main/java/com/ibm/plugin/OutputFileJob.java)).
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

It is not sufficient for a language to be supported by SonarQube plugin: must also integrate with the engine.

Update the pom.xml

Find the extension points:
https://docs.sonarsource.com/sonarqube/latest/analyzing-source-code/languages/overview/

## Adding support for another cryptography library