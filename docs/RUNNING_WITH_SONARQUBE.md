# Running the Plugin with SonarQube

This guide describes how to build the plugin, run it in a local SonarQube instance and scan a
project to generate a CBOM.

## Prerequisites

- Java 21
- Maven 3.9 or newer
- Docker with the Docker Compose plugin
- [SonarScanner CLI](https://docs.sonarsource.com/sonarqube-server/latest/analyzing-source-code/scanners/sonarscanner/)
  6.0 or newer

> [!IMPORTANT]
> The plugin requires Java 21 on both the SonarQube server and the scanner. SonarScanner CLI 6.0
> and newer obtain the required Java runtime from the server automatically. SonarScanner CLI 5.x
> uses its bundled Java 17 runtime and therefore must be configured to use Java 21: set
> `use_embedded_jre=false` in `bin/sonar-scanner` and set `JAVA_HOME` to a Java 21 installation.

## Build the plugin

From the repository root:

```bash
mvn clean package -DskipTests
```

The plugin JAR is copied to `.SonarQube/plugins/`, which the SonarQube container uses as its
plugins directory.

> [!NOTE]
> C/C++ support is bundled in the plugin JAR. Do not install the sonar-cxx plugin separately.

## Start SonarQube

From the repository root:

```bash
echo "UID=$(id -u)" > .env
docker compose up -d
```

Wait until SonarQube reports the status `UP`:

```bash
until curl -sf http://localhost:9000/api/system/status | grep -q '"status":"UP"'; do
  sleep 3
done
```

SonarQube is available at <http://localhost:9000>. The default credentials are `admin` /
`admin`.

## Configure SonarQube

The following steps use the SonarQube Web API. They can also be performed in the SonarQube UI
(see [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md)).

### Generate a token

```bash
curl -s -u admin:admin -X POST "http://localhost:9000/api/user_tokens/generate" \
  -d "name=my-scan-token"
```

Save the value of the `token` field. It is used to authenticate the scanner.

### Create a quality profile with the Inventory rule

The _Cryptographic Inventory (CBOM)_ rule generates the CBOM. It must be active in the quality
profile used by the project. Use the keys for the language to scan:

| Language | Language key | Rule key                        |
| -------- | ------------ | ------------------------------- |
| Java     | `java`       | `sonar-java-crypto:Inventory`   |
| Python   | `py`         | `sonar-python-crypto:Inventory` |
| Go       | `go`         | `sonar-go-crypto:Inventory`     |
| C/C++    | `cxx`        | `sonar-cpp-crypto:Inventory`    |

Example for C/C++:

```bash
curl -s -u admin:admin -X POST "http://localhost:9000/api/qualityprofiles/create" \
  -d "language=cxx&name=Cryptography"
```

Use the `key` of the created profile to activate the rule:

```bash
curl -s -u admin:admin -X POST "http://localhost:9000/api/qualityprofiles/activate_rule" \
  -d "key=<profile-key>&rule=sonar-cpp-crypto:Inventory"
```

### Create a project

```bash
curl -s -u admin:admin -X POST "http://localhost:9000/api/projects/create" \
  -d "project=my-project&name=my-project"
curl -s -u admin:admin -X POST "http://localhost:9000/api/qualityprofiles/add_project" \
  -d "qualityProfile=Cryptography&language=cxx&project=my-project"
```

## Scan a project

Run the scanner from the root directory of the project to scan.

### C/C++

```bash
sonar-scanner \
  -Dsonar.projectKey=my-project \
  -Dsonar.sources=src \
  -Dsonar.cxx.file.suffixes=.c,.cc,.cpp,.cxx,.c++,.h,.hh,.hpp,.hxx,.h++ \
  -Dsonar.host.url=http://localhost:9000 \
  -Dsonar.token=<your-token>
```

> [!IMPORTANT]
> `sonar.cxx.file.suffixes` is required. Without it, no C/C++ file is analyzed.

If the code depends on preprocessor macros or include directories defined by its build system,
set them with `sonar.cxx.defines` and `sonar.cxx.includeDirectories`. These settings are easier
to maintain in a `sonar-project.properties` file in the root directory of the scanned project:

```bash
sonar.projectKey=my-project
sonar.sources=src
sonar.cxx.file.suffixes=.c,.cc,.cpp,.cxx,.c++,.h,.hh,.hpp,.hxx,.h++
sonar.cxx.defines=USE_OPENSSL 1\n\
TLS1_3_VERSION 0x0304
sonar.cxx.includeDirectories=include
sonar.host.url=http://localhost:9000
sonar.token=<your-token>
```

With this file in place, run `sonar-scanner` without arguments.

### Java

Compile the project first, then run:

```bash
sonar-scanner \
  -Dsonar.projectKey=my-project \
  -Dsonar.sources=src/main/java \
  -Dsonar.java.binaries=target/classes \
  -Dsonar.java.libraries=<path/to/library.jar> \
  -Dsonar.host.url=http://localhost:9000 \
  -Dsonar.token=<your-token>
```

`sonar.java.binaries` must point to the compiled classes. `sonar.java.libraries` must list the
JARs of the cryptography libraries used by the code, such as BouncyCastle.

### Python and Go

```bash
sonar-scanner \
  -Dsonar.projectKey=my-project \
  -Dsonar.sources=. \
  -Dsonar.host.url=http://localhost:9000 \
  -Dsonar.token=<your-token>
```

## Results

After a successful scan, the scanner prints the CBOM statistics and writes `cbom.json` to the
directory it was run from. The file name can be changed with the `sonar.cryptoScanner.cbom`
property (see [Configuration](../README.md#configuration)). The detected assets are also listed
in the _Issues_ tab of the project in SonarQube.

If no CBOM is generated, check that:

1. The Inventory rule is active in the quality profile assigned to the project.
2. The scanner runs on Java 21.
3. For Java, `sonar.java.binaries` and `sonar.java.libraries` point to existing files.
4. For C/C++, `sonar.cxx.file.suffixes` is set.

## Stop SonarQube

Stop the containers and keep the data:

```bash
docker compose down
```

To also delete all SonarQube data:

```bash
docker compose down -v
```
