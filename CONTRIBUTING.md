# Contributing

The Sonar Cryptography Plugin is an open source project that aims to create 
an easy way to discover the use of cryptography in source code and create CBOM. 
This page describes how you can join the community in this goal.

## Before you start

If you are new to the community? We recommend you do the following before diving into the code:

* Read the [Code of Conduct](https://github.com/IBM/sonar-cryptography/blob/main/CODE_OF_CONDUCT.md)
* Familiarize yourself with the community (via [GitHub](https://github.com/IBM/sonar-cryptography/discussions) etc.)

## Choose an issue to work on
The Sonar Cryptography Plugin uses the following labels to help non-maintainers find issues best suited to their interest and experience level:

* [good first issue](https://github.com/IBM/sonar-cryptography/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) - these issues are typically the simplest available to work on, ideal for newcomers. They should already be fully scoped, with a clear approach outlined in the descriptions.
* [help wanted](https://github.com/IBM/sonar-cryptography/issues?q=is%3Aopen+is%3Aissue+label%3A%22help+wanted%22) - these issues are generally more complex than good first issues. They typically cover work that core maintainers don't currently have capacity to implement and may require more investigation/discussion. These are a great option for experienced contributors looking for something a bit more challenging.

## Code Style

Check if all java files are well formated and license headers are in place.
```shell
mvn spotless:check
```
Applies format and license headers to files.
```shell
mvn spotless:apply
```
Spotless Maven Documentation: https://github.com/diffplug/spotless/blob/main/plugin-maven/README.md

Check for coding style
```shell
mvn checkstyle::check
```

## Build

Execute the following command in the project directory:
```shell
mvn clean package
```
The `.jar` file will be stored in the target directory and also copied to
`.SonarQube/plugins`.

## Run the Plugin with SonarQube

```shell
# starts a postgres database and a sonarqube instance 
docker-compose up
```

### Configure SonarQube

For the initial configuration and setup, 
take a look at the [official SonarQube documentation](https://docs.sonarqube.org/latest/try-out-sonarqube/).

