## OpenSSLFIPSProvider Algorithms

### Introduction
The OpenSSLFIPSProvider Java security provider is a FIPS-compliant security provider that presents a Java layer over FIPS 140-3 certified OpenSSL on Ubuntu 22.04. Under the hood, it invokes the [OpenSSL EVP API](https://docs.openssl.org/3.3/man7/evp/) and the uses cryptography implementations from the [OSSL_PROVIDER_FIPS](https://docs.openssl.org/3.0/man7/OSSL_PROVIDER-FIPS/) module. Classes in the OpenSSLFIPSProvider implement a part of the Service Provider Interface defined in the [java.security](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/package-summary.html) package. The main [Provider](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/Provider.html) class is [OpenSSLFIPSProvider](https://github.com/canonical/openssl-fips-java/blob/main/src/main/java/com/canonical/openssl/provider/OpenSSLFIPSProvider.java).

**Note**: the OpenSSLFIPSProvider is "FIPS-compliant" if and only if the underlying OpenSSL library is "FIPS-certified". 

### Basic usage instructions
Please refer to this section in the README for instructions on configuring the [OpenSSL FIPS module](https://github.com/canonical/openssl-fips-java?tab=readme-ov-file#install-and-configure-openssl-fips).

The provider is compiled with OpenJDK 17. It can used it with OpenJDK 17 and later versions. To be able to instantiate algorithms from this provider, you may adopt one of the following approaches:

1. Modify the java.security file to define this provider at the top of the provider list:
   ```
   security.provider.1=com.canonical.openssl.provider.OpenSSLFIPSProvider
   ```
2. Maintain a separate java.security file and supply it to the JVM through the `java.security.properties` system property.

3. Use the [addProvider() method](https://docs.oracle.com/javase/7/docs/api/java/security/Security.html#addProvider(java.security.Provider) to dynamically add the provider.

In each of the three cases above, the OpenSSLFIPSProvider must be present on the CLASSPATH.

### List of supported security algorithms

The Java OpenSSLFIPSProvider supports a subset of the algorithms and operations supported by the underlying OpenSSL's [OSSL_PROVIDER_FIPS](https://docs.openssl.org/3.0/man7/OSSL_PROVIDER-FIPS/#description) module. They are listed below in Java-security parlance.

#### Deterministic Random Bit Generators
| Algorithm name| Algorithm reference in OpenSSL | Description |
|----------------|------------------------------------|------------|
|AES256CTR|[EVP_RAND-CTR-DRBG](https://docs.openssl.org/3.0/man7/EVP_RAND-CTR-DRBG/)| |
|HashSHA512|[EVP_RAND-HASH-DRBG](https://docs.openssl.org/3.0/man7/EVP_RAND-HASH-DRBG/)||
|HMACSHA256|[EVP_RAND-HMAC-DRBG](https://docs.openssl.org/3.0/man7/EVP_RAND-HMAC-DRBG/)||

#### Symmetric Ciphers
| Algorithm name| Algorithm reference in OpenSSL EVP | Description |
|----------------|------------------------------------|------------|
| AES[key-size]/[mode]/[padding] * | [EVP_CIPHER-AES](https://docs.openssl.org/3.0/man7/EVP_CIPHER-AES/) | |
* The supported key-sizes are 128, 192 and 256.
* The supported modes are `ECB`, `CBC`, `CFB1`, `CFB8`, `CTR`, `CCM` and `GCM`.
* The support paddings are `NONE`, `PKCS7`, `PKCS5`, `ISO10126_2`, `ISO7816_4`, `X9_23`
* Examples of valid algorithm names: `AES256/CBC/NONE` and `AES128/CTR/PKCS5`

#### Key Agreement
| Algorithm name| Algorithm reference in OpenSSL EVP | Description |
|----------------|------------------------------------|------------|
| DH | [EVP_KEYEXCH-DH](https://docs.openssl.org/3.0/man7/EVP_KEYEXCH-DH/)| Diffie-Hellman |
| ECDH | [EVP_KEYEXCH-ECDH](https://docs.openssl.org/3.0/man7/EVP_KEYEXCH-ECDH/) | Elliptic-Curve Diffie Hellman |

#### Key Encapsulation
| Algorithm name| Algorithm reference in OpenSSL EVP | Description |
|----------------|------------------------------------|------------|
| RSA | [EVP_KEM-RSA](https://docs.openssl.org/3.0/man7/EVP_KEM-RSA/)||

#### Message Authentication Code
| Algorithm name| Algorithm reference in OpenSSL EVP | Description |
|----------------|------------------------------------|------------|
|CMACwithAes256CBC|[EVP_MAC-CMAC](https://docs.openssl.org/3.0/man7/EVP_MAC-CMAC/)||
|GMACWithAes128GCM|[EVP_MAC-GMAC](https://docs.openssl.org/3.0/man7/EVP_MAC-GMAC/)||
|HMACwithSHA1|[EVP_MAC-HMAC](https://docs.openssl.org/3.0/man7/EVP_MAC-HMAC/)||
|HMACwithSHA3_512|[EVP_MAC-HMAC](https://docs.openssl.org/3.0/man7/EVP_MAC-HMAC/)||
|KMAC128|[EVP_MAC-KMAC](https://docs.openssl.org/3.0/man7/EVP_MAC-KMAC/)||
|KMAC256|[EVP_MAC-KMAC](https://docs.openssl.org/3.0/man7/EVP_MAC-KMAC/)||

#### Message Digests
| Algorithm name| Algorithm reference in OpenSSL EVP | Description |
|----------------|------------------------------------|------------|
|MDKeccakKemak128|||
|MDKeccakKemak256|||
|MDSHA1|||
|MDSHA224|||
|MDSHA256|||
|MDSHA384|||
|MDSHA3_224|||
|MDSHA3_256|||
|MDSHA3_384|||
|MDSHA3_512|||

#### Key Definition Functions
| Algorithm name| Algorithm reference in OpenSSL EVP | Description |
|----------------|------------------------------------|------------|
|PBKDF2|[EVP_KDF-PBKDF2](https://docs.openssl.org/3.0/man7/EVP_KDF-PBKDF2/)||

#### Digital Signatures
| Algorithm name| Algorithm reference in OpenSSL EVP | Description |
|----------------|------------------------------------|------------|
|RSAwithSHA256|[EVP_SIGNATURE-RSA](https://docs.openssl.org/3.0/man7/EVP_SIGNATURE-RSA/)||
