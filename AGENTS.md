# Repository Guidelines

## Project Structure & Module Organization

This is a Java 17, multi-module Maven project. `sonar-cryptography-plugin/` registers the SonarQube plugin. `java/`, `python/`, `go/`, and `csharp/` implement language detection; `engine/` provides shared detection logic. `mapper/`, `enricher/`, and `output/` turn findings into a cryptographic bill of materials. Shared code lives in `common/` and `rules/`. Each module keeps production code in `src/main/java` and tests in `src/test/java`; language test inputs live under `src/test/files/`. See `docs/` for rule and language-extension guides.

## Build, Test, and Development Commands

- `mvn clean package`: build all modules and run tests, as CI does.
- `mvn test`: run the test suite without packaging.
- `mvn test -pl java`: run one module's tests; replace `java` with another module name.
- `mvn spotless:check`: check Java formatting and license headers.
- `mvn spotless:apply`: format Java files and apply required headers.
- `mvn checkstyle:check`: check Java style rules.
- `docker-compose up`: start the local PostgreSQL and SonarQube services after building the plugin.

## Coding Style & Naming Conventions

Use Spotless's Google Java Format in AOSP style for Java indentation, imports, and annotations. Keep the Apache 2.0 license header on Java files. Follow existing package names in lowercase, Java types in `UpperCamelCase`, and methods and fields in `lowerCamelCase`. Checkstyle runs during Maven's `validate` phase; run formatting and style checks before submitting changes.

## Testing Guidelines

Tests use JUnit 5 and AssertJ. Name test classes `*Test.java` and place them beside the corresponding module's code under `src/test/java`. For detection rules, add representative source fixtures under that module's `src/test/files/` and assert the detected findings. Run `mvn test` for broad changes or `mvn test -pl <module>` for focused changes. No numeric coverage threshold is configured in the parent build.

## Commits & Pull Requests

Recent commits commonly use short subjects such as `feat: ...`, `fix: ...`, `ci: ...`, and `chore(deps): ...`; some use plain descriptive subjects. Keep the subject specific and include an issue or PR reference when applicable. In pull requests, describe the behavior changed, affected modules, and commands run; link the relevant issue. Add screenshots only for visible SonarQube interface changes.
