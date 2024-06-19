# Writing new detection rules for the Sonar Cryptography Plugin

The Sonar Cryptography Plugin is designed with a modular architecture so that you can easily write new detection rules for cryptography assets.
Here, we explain in detail our powerful high-level syntax that you can use to define a detection rule in a few lines, independently of the programming language of the source code.

> [!IMPORTANT]
> If the programming language that you want to scan is not yet supported by our plugin, or if you want to add support for a cryptography library from scratch, please read [*Extending the Sonar Cryptography Plugin to add support for another language or cryptography library*](./LANGUAGE_SUPPORT.md) in parallel.

### Writing a detection rule

For a relatively easy and short syntax, we follow the [builder design pattern](https://refactoring.guru/design-patterns/builder) to let you construct detection rules step by step.
The interface specifying precisely this builder pattern (the allowed ordering of the construction steps) is [`IDetectionRule`](../engine/src/main/java/com/ibm/engine/rule/IDetectionRule.java).

#### Specification

Because visualizing the pattern from this interface is not trivial, we provide below a *regex-like* specification indicating how you can order the construction steps.
It contains these three *regex-like* syntax elements:
- `[ ... ]?` represents an optional builder statement
- `[ ... ]*` represents zero or more repetitions of the enclosed statement
- `A | B` indicates that exactly one of A or B must be chosen

```java
new DetectionRuleBuilder<T>()
     .createDetectionRule()
     .forObjectTypes(types) | .forObjectExactTypes(types)
     .forMethods(names) | .forConstructor()
     [.shouldBeDetectedAs(actionFactory)]?
     [
         .withMethodParameter(type) | .withMethodParameterMatchExactType(type)
         [
             .shouldBeDetectedAs(actionFactory)
             [.asChildOfParameterWithId(id)]?
         ]?
         [.addDependingDetectionRules(detectionRules)]?
     ]*
     .buildForContext(detectionValueContext)
     .inBundle(bundle)
     .withDependingDetectionRules(detectionRules) | .withoutDependingDetectionRules()
```

#### Detailed explanations



### Translating findings of a detection rule

### Reorganizing the translation tree

> TODO:
> - detection rules format
> - translation
> - reorganizer rules