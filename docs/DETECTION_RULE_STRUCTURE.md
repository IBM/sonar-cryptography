# Writing new detection rules for the Sonar Cryptography Plugin

The Sonar Cryptography Plugin is designed with a modular architecture so that you can easily write new detection rules for cryptography assets.
Here, we explain in detail our powerful high-level syntax that you can use to define a detection rule in a few lines, independently of the programming language of the source code.

> [!IMPORTANT]
> If the programming language that you want to scan is not yet supported by our plugin, or if you want to add support for a cryptography library from scratch, please read [*Extending the Sonar Cryptography Plugin to add support for another language or cryptography library*](./LANGUAGE_SUPPORT.md) in parallel.

### Writing a detection rule

For a relatively easy and short syntax, we follow the [builder design pattern](https://refactoring.guru/design-patterns/builder) to let you construct detection rules step by step.
The interface specifying precisely this builder pattern (the allowed ordering of the construction steps) is [`IDetectionRule`](../engine/src/main/java/com/ibm/engine/rule/IDetectionRule.java).

The entry-point of a detection rule is a function call (or similarly a class instantiation).
A cryptography library will indeed provide you with various functions you can call to perform a cryptographic operation.
The information about the involved cryptography assets can be part of the function name (a function called `aesEncrypt()`), of the function arguments (a function `encrypt(String algorithmName)`) or of the object on which the function is called (an `encrypt()` function called on a `crypto.AES` object).
Sometimes, it is a mix of everything.
But in every case there is a function call, which is why it is what we are aiming to detect with our detection rules.

#### Specification

Because visualizing the builder pattern from the [`IDetectionRule`](../engine/src/main/java/com/ibm/engine/rule/IDetectionRule.java) interface is not trivial, we provide below a *regex-like* specification indicating how you can order the construction steps to detect a function call.
It contains these three *regex-like* syntax elements:
- `[ ... ]?` represents an optional builder statement
- `[ ... ]+` represents one or more repetitions of the enclosed statement
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
             .shouldBeDetectedAs(valueFactory)
             [.asChildOfParameterWithId(id)]?
         ]?
         [.addDependingDetectionRules(detectionRules)]?
     ]+
     .buildForContext(detectionValueContext)
     .inBundle(bundle)
     .withDependingDetectionRules(detectionRules) | .withoutDependingDetectionRules()
```

You may have noticed that this specification does not allow constructing rules for function calls with no parameters.
Indeed, to keep the specification above simpler, we handle this case separately [later](#special-cases-no-parameters-and-any-parameters).

#### Detailed explanations

Writing a detection rule starts with instantiating a new [`DetectionRuleBuilder`](../engine/src/main/java/com/ibm/engine/rule/builder/DetectionRuleBuilder.java) and calling its `createDetectionRule()` method.
Notice that `DetectionRuleBuilder<T>` is a generic class, that should be parametrized with a language-specific type (learn more [here](./LANGUAGE_SUPPORT.md#identifying-the-four-classes-to-use-in-generics)).
Then, the two next builder steps aim at identifying the function call that you want to capture, by specifying first its type and then its name.

To specify its type(s), you can use `forObjectTypes(String... types)` to capture any function call that is called on an object whose type is matching one of the provided types **or subtypes**. Instead, you can also use `.forObjectExactTypes(String... types)` to only capture function calls matching one of the provided exact types (and not their subtypes).

> [!NOTE]
> Some languages, like Python, can have functions defined directly in a file and not in a class, in this case the function is not "called on an object". In this case, the meaning of the provided types depends on the implementation of the language support for the Sonar Cryptography Plugin: you should look into the documentation or code describing what this "object type" represents in your language. In particular, you can look into the implementation of the function `getInvokedObjectTypeString` in the [`ILanguageTranslation`](../engine/src/main/java/com/ibm/engine/language/ILanguageTranslation.java) implementation of your language. For example in Python, we define this type as the "fully qualified name" of the function, which is its full import path.

You then have to specify the name(s) of the function you want to capture using `forMethods(String... names)`.
Alternatively, you can use `forConstructor()` to capture constructors of the object specified previously (note that constructors are internally defined as `<init>` functions).

Then, you can add an optional `shouldBeDetectedAs(IActionFactory<T> actionFactory)` step.
This allows you to capture some information related to your function (and not its parameters).
The information that you capture must be a [`IActionFactory`](../engine/src/main/java/com/ibm/engine/model/factory/IActionFactory.java), so typically an action like "encrypt" or "hash". Several classes already implement `IActionFactory` and offer to choose among common actions.
Alternatively, [`ValueActionFactory`](../engine/src/main/java/com/ibm/engine/model/factory/ValueActionFactory.java) allows you to capture any string value that you provide.
For example, for a function call `initAes()` or `AES.init()`, here is the place to capture the use of the AES algorithm, using `shouldBeDetectedAs(new ValueActionFactory<>("AES")`.

> [!IMPORTANT]
> In detection rules, `shouldBeDetectedAs` are the only statements which specify the "capture" of information, that will be stored in a tree structure. It can be done at the top level of a detection rule (like we just explained), or at the level of a function parameter (explained later below). 

At this point, to identify the exact function call that we want to detect, we have to specify all the parameters of the function call.
We therefore add `withMethodParameter(String type)` for each parameter, with its type.
Similarly to previously, we can use `withMethodParameterMatchExactType(String type)` instead, if we want to capture function calls where the parameter matches with the exact type (and not a subtype).

Then, below each specified method parameter, we can optionally capture the value of this parameter using `shouldBeDetectedAs(IValueFactory<T> valueFactory)`.
This is similar to the `shouldBeDetectedAs(IActionFactory<T> actionFactory)` step, but we now capture parameter information in the form of a [`IValueFactory`](../engine/src/main/java/com/ibm/engine/model/factory/IValueFactory.java).
We offer multiple classes implementing `IValueFactory` allowing you to capture various information. Here are two common examples:
- The parameter contains a string specifying the chosen algorithm (like in the function call `encrypt("AES")`): `shouldBeDetectedAs(new AlgorithmFactory<>())` will capture the string `AES`.
- The parameter contains an integer specifying the bit size of the key (like in the function call `createNewKeyWithSize(256)`): `shouldBeDetectedAs(new KeySizeFactory<>(Size.UnitType.BIT))` will capture the integer `256`.

This step may optionally be followed by a `asChildOfParameterWithId(int id)` statement, which give finer-grained control on the organization of the tree of detected values.
Indeed, by default, all values detected with `shouldBeDetectedAs` in a same rule are set at the same level in the tree of detections (no matter if it's a top level or a parameter detection).
The step `asChildOfParameterWithId` allows you to put the associated detected value below (in the tree) the detection identified by `id`.
The `id` of a detected value is `-1` if it comes from the top level detection, or the index (starting at `0`) of the parameter detection of the rule.
> TODO: is it the index of the parameter, or the index of the `shouldBeDetectedAs` of parameters?



#### Example
> Use asChildOfParameterWithId to showcase what it does

#### Special cases: no parameters and any parameters


### Translating findings of a detection rule

### Reorganizing the translation tree

> TODO:
> - detection rules format
> - translation
> - reorganizer rules