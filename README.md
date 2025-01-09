# KRITIS³M Public Key Infrastructure

This repository contains the code for the Public Key Infrastructure (PKI) for the KRITIS³M research project.

**Disclaimer:** It is highly recommended to consume this repository indirectly via the [KRITIS³M Workspace repository](https://github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_workspace).

The code is split into two C libraries containing the actual PKI functionality and into CLI tooling for direct usage from the command line. The libraries can also be used from within other projects, for example the [KRITIS³M EST code](https://github.com/Laboratory-for-Safe-and-Secure-Systems/est).

## Building

The project uses CMake to be built. By default, both the libraries and the CLI tools are built. The CLI tools may be disabled with the `KRITIS3M_PKI_LIBRARY_ONLY` CMake variable (`-DKRITIS3M_PKI_LIBRARY_ONLY=ON`).

```bash
mkdir build && cd build
cmake [options] ..
make
sudo make install
```

You can also use Ninja as a build tool by specifying `-GNinja` within the CMake invocation.

The libraries and CLI tools have a few dependencies listed below. By default, those are cloned using CMake the FetchContent functionality. However, you can also specify their source directory via CMake variables (given below for each dependency) to prevent additional downloads.

* [kritis3m_applications](https://github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_applications): common code for CLI applications (`-DFETCHCONTENT_SOURCE_DIR_KRITIS3M_APPLICATIONS=/path/to/kritis3m_applications`).
* [kritis3m_wolfssl](https://github.com/Laboratory-for-Safe-and-Secure-Systems/kritis3m_wolfssl): Wrapper repository for the WolfSSL fork and the liboqs library with the specific configuration of both libraries (`-DFETCHCONTENT_SOURCE_DIR_KRITIS3M_WOLFSSL=/path/to/kritis3m_wolfssl`).
* [wolfssl](https://github.com/Laboratory-for-Safe-and-Secure-Systems/wolfssl): KRITIS³M fork of WolfSSL with downstream changes (`-DFETCHCONTENT_SOURCE_DIR_WOLFSSL=/path/to/wolfssl`).
* [liboqs](https://github.com/open-quantum-safe/liboqs): Library for support of the PQC algorithm FALCON (`-DFETCHCONTENT_SOURCE_DIR_LIBOQS=/path/to/liboqs`).

The resulting libraries (and CLI tools) are installed in the default CMake installation paths. Another install path may be specified via the default CMake `CMAKE_INSTALL_PREFIX` variable.

### CLI build options

The following additional CMake options are available to customize the compilation of the CLI tools:

* `KRITIS3M_PKI_TOOLS_SELF_CONTAINED`: When enabled, the CLI tools will be built as a self-contained executables with all dependencies statically included. This also prevents that any libraries are installed during system-wide installation of the tools. When disabled, the tools dynamically load the dependencies at runtime. This installs all dependencies system-wide, too. Default: `OFF`.
* `KRITIS3M_PKI_INSTALL_LIBRARIES`: When enabled, the compiled PKI libraries and their dependencies are installed system-wide, too. When disabled, only the executables are installed. Only relevant when building self-contained tools (see above). Default: `OFF`.
* `KRITIS3M_PKI_BUILD_SE_IMPORTER`: When enabled, the optional helper tool kritis3m_se_importer is built. This tool imports an existing private key into a PKCS#11 token. Default: `OFF`.

In addition to these options, the library options in the next section also influence the CLI tools.

### Library build options

The following additional CMake options are available to customize the compilation of the two PKI libraries:

* `BUILD_SHARED_LIBS`: Select between shared libraries (.so/.dll) and static libraries (.a/.lib). Default: `ON`.
* `KRITIS3M_PKI_STANDALONE`: When this option is enabled, the kritis3m_wolfssl dependency will be built as standalone library to be installed system-wide. When disabled, the library will be built as a local library only to be linked against a wrapping application. Default: `ON`.
* `KRITIS3M_PKI_EXTERNAL_WOLFSSL`: Use an externally installed WolfSSL library (searched using CMake `find_package()`). If disabled, WolfSSL will be built. Default: `OFF`.
* `KRITIS3M_PKI_ENABLE_FALCON`: Enable support for the PQC signature algorithm FALCON (FN-DSA) via the liboqs library. When disabled, the library will not be built. Default: `ON`.
* `KRITIS3M_PKI_COMBINED_STATIC_LIB`: Create combined static libraries that include all dependencies. Default: `OFF`.

### Bash completions

For the CLI tools, a script with bash completions is provided in `cli_tools/scripts/`.

## CLI Tools

Two CLI tools are provided to use the PKI from the command line: the main `kritis3m_pki` tool, and the optional small helper tool `kritis3m_se_importer` to import existing private keys into a PKCS#11 token.

### Main PKI tool (kritis3m_pki)

This main tool provides access to all implemented features of the PKI client and server libraries:
* Create new private keys
* Create Certificate Signing Requests (CSR) to obtain a new entity certificate
* Issue new certificates (from an existing CRSR or directly for a newly created private key)
    * CA certificates
    * Machine certificates
    * Person certificates (for e.g. S/MIME)

You can provide various metadata for the certificate/CSR via CLI arguments. Please refer to the output of `kritis3m_pki --help` for further information.

The currently supported algorithm for key generation are:
* RSA: 2048 bit, 3072 bit, and 4096 bit key length
* ECC: secp256, secp384, secp521 curves
* Edwards curves: ed25519, ed448
* ML-DSA (FIPS204): mldsa44, mldsa65, mldsa87
* Dilithium (NIST round 3 version): dilithium2, dilithium3, dilithium5

FN-DSA (FALCON) is supported for CSR/certificate issuance, but not for key generation. Hence, private keys must be generated for example with OpenSSL and OQS provider.

All input files containing private keys/certificates/CSRs have to be encoded in PEM format. Output files are also encoded in PEM.

The tool also supports the generation of hybrid certificates containing both classical and PQC key material (public keys and CA signatures). For more information on that topic, please see [here](ToDo). You can handle the alternative private keys with the related CLI arguments.

#### PKCS#11

In addition, private keys stored on external tokens available via a PKCS#11 library can be used for both the entitiy or the issuer key. Furthermore, new private keys can also be generated directly on the token.

You have to specify the path to the module library via the proper CLI arguments. Additionally, a slot to be used and the PIN for the token can optionally be provided.

Private keys on a token are identified with the PKCS#11 label string. You have two options to provide this label to the CLI tool. You can either enter the label directly via the `--issuer_key` and `--entity_key` arguments by prepending the string with "pkcs11:" instead of a path to a PEM file (also see examples below). The other option is to store the exact same string with the prepending "pkcs11:" in a file and provide that via the `--issuer_key` and `--entity_key` arguments.

When a new private key is generated on a PKCS#11 token and the `--key_out` argument is provided, the label of the key is stored in a file with that string format.

### Helper tool to import private keys into PKCS#11 token

Please see the output of `kritis3m_se_importer --help` for further information.

### Examples

The following examples demonstrate the usage of the main PKI tool (kritis3m_pki). It is assumed that the tool is available in the `PATH` variable.

By default, the tool only creates output in case of an error. Verbose output can be enabled with `-v` or `--verbose`, debug output with `-d` or `--debug`.

#### Generate a private key
```bash
kritis3m_pki --gen_key mldsa44 --key_out private_key.pem
```

#### Generate a CSR with a new private key
```bash
kritis3m_pki --gen_key mldsa44 --key_out private_key.pem --csr_out csr.pem \
             --common_name "Test Cert" --org "Example Org" --unit "Example Unit" \
             --alt_names_DNS "www.example.com"
```
Data provided via the arguments `--alt_names_DNS`, `--alt_names_URI`, `--alt_names_IP`, and `--alt_names_email` are placed in the Subject Alternative Name (SAN) extension. More than one value can be provided, separated by a semicolon.

#### Create a self-signed CA certificate
```bash
kritis3m_pki --gen_key mldsa44 --key_out root_key.pem --cert_out root.pem \
             --common_name "Test Root" --org "Example Org" \
             --CA_cert --self_signed_cert --validity 365
```

#### Create a intermediate CA certificate
```bash
kritis3m_pki --gen_key mldsa44 --key_out inter_key.pem --cert_out inter.pem \
             --issuer_cert root.pem --issuer_key root_key.pem \
             --common_name "Test Intermediate" --org "Example Org" \
             --CA_cert --validity 365
```

#### Issue a entity certificate from a CSR
```bash
kritis3m_pki --csr_in csr.pem --cert_out entity.pem \
             --issuer_cert inter.pem --issuer_key inter_key.pem \
             --validity 365
```

#### Create a machine entity certificate from a newly generated private key
```bash
kritis3m_pki --gen_key mldsa44 --key_out entity_key.pem --cert_out entity.pem \
             --issuer_cert inter.pem --issuer_key inter_key.pem \
             --common_name "Test Cert" --org "Example Org" --unit "Example Unit" \
             --alt_names_DNS "www.example.com" --validity 365
```

#### Create a human certificate (S/MIME) with a new private key
```bash
kritis3m_pki --gen_key mldsa44 --key_out person_key.pem --cert_out person.pem \
             --issuer_cert inter.pem --issuer_key inter_key.pem \
             --common_name "Test Person" --org "Example Org" --unit "Example Unit" \
             --email "person@example.com" --alt_names_email "person@example.com" \
             --human_cert --validity 365
```

#### Generate a certificate with the private key on a PKCS#11 token
```bash
kritis3m_pki --gen_key mldsa44 --key_out entity_key.pem --cert_out entity.pem \
             --entity_key pkcs11:TEST_KEY \
             --issuer_cert inter.pem --issuer_key inter_key.pem \
             --common_name "Test Cert" --org "Example Org" --unit "Example Unit" \
             --alt_names_DNS "www.example.com" --validity 365 \
             --p11_entity_module /path/to/library.so
```
The new file `entity_key.pem` now contains the string "pkcs11:TEST_KEY" for later use. This is optional, however, and the `--key_out` parameter may be left out. In this case, the label must be remembered by the user.

#### Issue a certificate using a private key on a PKCS#11 token
```bash
kritis3m_pki --gen_key mldsa44 --key_out entity_key.pem --cert_out entity.pem \
             --issuer_cert inter.pem --issuer_key pkcs11:ISSUER_KEY \
             --common_name "Test Cert" --org "Example Org" --unit "Example Unit" \
             --alt_names_DNS "www.example.com" --validity 365 \
             --p11_issuer_module /path/to/library.so
```
This assumes that on the PKCS#11 token the private key for the issuer certificate is already present and can be found using the label "ISSUER_KEY".

## Libraries

### Common code

### Client library

### Server library
