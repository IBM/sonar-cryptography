# Development

## Code Style

### Format 

Check if all java files are well formated and license headers are in place.
```shell
mvn spotless:check
```
Applies format and license headers to files.
```shell
mvn spotless:apply
```

Spotless Maven Documentation: https://github.com/diffplug/spotless/blob/main/plugin-maven/README.md

### Coding

Check for coding style
```shell
mvn checkstyle::check
```

## Development

> To visulize the detection rules visit the github page https://pages.github.com/IBM/sonar-cryptography

## Build

### Build the Plugin

In the project directory run the following command:
```shell
mvn clean package
```
The `.jar` file will be stored in the target directory and also copied to 
`.SonarQube/plugins`.

## Deploy

### Set a new version

```shell
mvn versions:set -DnewVersion=1.0.0-SNAPSHOT
```
If you made a mistake, do

```shell
mvn versions:revert
```

afterwards, or

```shell
mvn versions:commit
```

if you're happy with the results.

## Run the Plugin with SonarQube

### Run SonarQube with Docker Compose

```shell
UID=${UID} GID=${GID} docker-compose up
```

### Configure SonarQube

For the initial configuration and setup have a look to the [official SonarQube documentation](https://docs.sonarqube.org/latest/try-out-sonarqube/).

### Create a Quality Profile with Crypto Rules

See detailed instructions in the root [README.md](./README.md#create-a-quality-profile-with-crypto-rules)
