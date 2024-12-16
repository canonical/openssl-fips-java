### Introduction
The OpenSSL FIPS Java project is a Java FIPS security provider module layered on top of the [OpenSSL library and its FIPS module](https://docs.openssl.org/3.0/man7/OSSL_PROVIDER-FIPS/). Complying with the [Java Cryptography Architecture](https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html), it implements the Java security SPI classes for security functions including [Deterministic Random Bit Generators](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/SecureRandomSpi.html), [Ciphers](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/javax/crypto/CipherSpi.html), [Key Agreements](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/javax/crypto/KeyAgreementSpi.html), [Key Derivations](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/javax/crypto/SecretKeyFactorySpi.html), [Key Encapsulation](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/javax/crypto/KEMSpi.html), [Message Digests](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/MessageDigest.html#:~:text=Message%20digests%20are%20secure%20one,called%20to%20reset%20the%20digest.), [Message Authentication Codes](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/javax/crypto/Mac.html) and [Signatures](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/Signature.html?source=%3Aso%3Atw%3Aor%3Aawr%3Aosec%3A%2C%3Aso%3Atw%3Aor%3Aawr%3Aosec%3A).

Under the covers, OpenSSL FIPS Java is quite tightly coupled with OpenSSL through the [Java Native Interface](https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/intro.html) and the [OpenSSL EVP API](https://docs.openssl.org/3.3/man7/evp/). Only FIPS-approved algorithms, offered by the OpenSSL FIPS module are registered with this provider. The binaries produced from this source should be generally considered FIPS-compliant if the underlying OpenSSL module is FIPS 140-2/140-3 certified.

### Structure of the source code
| Directory | Functionality |
|-----------|---------------|
| src/main/java/com/canonical/openssl | Java classes, including SPI implementations |
| src/main/native/c | C code that invokes OpenSSL EVP API, JNI code |
| src/main/native/include | JNI headers and library header files |
| src/test | C and Java tests | 

### Instructions to build and test the provider
#### Install and configure OpenSSL FIPS
You should skip this step if you have OpenSSL and OpenSSL FIPS module installed. Here are the commands for Ubuntu/Debian installations:
```
git clone https://github.com/openssl/openssl && cd openssl
git checkout openssl-3.0.2
sudo apt update && sudo apt install build-essential -y
./Configure enable-fips && make && sudo make install && sudo make install_fips
```
Create a FIPS module configuration file which will be loaded by the provider. Please keep this file under `/usr/local/ssl` only.
```
sudo mkdir -p /usr/local/ssl
sudo openssl fipsinstall -out /usr/local/ssl/fipsmodule.cnf -module /usr/local/lib64/ossl-modules/fips.so
ln -s /usr/local/lib64/ossl-modules/fips.so /usr/lib/x86_64-linux-gnu/ossl-modules/fips.so
```
#### Open the OpenSSL config file
```
sudo nano $(openssl version -d | awk '{gsub (/"/, "", $2); print $2}')/openssl.cnf 
```
#### Add the following to the config file of OpenSSL
```
config_diagnostics = 1
openssl_conf = openssl_init

.include /usr/local/ssl/fipsmodule.cnf

[openssl_init]
providers = provider_sect
alg_section = algorithm_sect

[provider_sect]
fips = fips_sect
base = base_sect

[algorithm_sect]
default_properties = fips=yes
```
#### Install OpenJDK v17
This project needs OpenJDK 17 or a later release of it. On Ubuntu/Debian systems, you may install the OpenJDK from the archive.
```
sudo apt update
sudo apt install openjdk-17-jdk-headless
```
#### Clone the project, build and test
This set of commands may be used on Ubuntu/Debian systems.
```
git clone https://github.com/canonical/openssl-fips-java && cd openssl-fips-java
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64/
export OPENSSL_MODULES=/usr/local/lib64/ossl-modules
mvn -B package --file pom.xml
```
Refer to this [GitHub Action](https://github.com/canonical/openssl-fips-java/blob/main/.github/workflows/maven.yml) for more details.
