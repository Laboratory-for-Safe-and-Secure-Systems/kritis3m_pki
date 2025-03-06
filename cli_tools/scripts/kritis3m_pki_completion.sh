#!/bin/bash

# Help prints:
#
# Usage: kritis3m_pki [OPTIONS]
#
# Key input:
#   --issuer_key <file>         Path to the primary issuer key (PEM)
#   --issuer_alt_key <file>     Path to the alternative issuer key (PEM; generate hybrid cert)
#   --entity_key <file>         Path to the primary entity key (PEM; same as issuerKey for self-signed cert)
#   --entity_alt_key <file>     Path to the alternative entity key (PEM; same as issuerAltKey for self-signed cert)
#
# Certificate/CSR input:
#   --issuer_cert <file>        Path to the issuer certificate (PEM)
#   --csr_in <file>             Path to a CSR (PEM)
#
# Key generation:
#   Currently supported algorithms: rsa2048, rsa3072, rsa4096
#                                   secp256, secp384, secp521
#                                   ed25519, ed448
#                                   mldsa44, mldsa65, mldsa87
#                                   falcon512, falcon1024
#   --gen_key <alogrithm>       Algorithm for key generation (see list above)
#   --gen_alt_key <alogrithm>   Algorithm for alternative key generation (see list above)
#
# Output:
#   --cert_out <file>           Path to the root certificate output file (PEM)
#   --csr_out <file>            Path to the CSR output file (PEM)
#   --key_out <file>            Path to the primary key output file (PEM)
#   --alt_key_out <file>        Path to the alternative key output file (PEM)
#
# Metadata:
#   --common_name <string>      Common Name (CN) for the certificate/CSR
#   --country <string>          Country (C) for the certificate/CSR
#   --state <string>            State (ST) for the certificate/CSR
#   --org <string>              Organization (O) for the certificate/CSR
#   --unit <string>             Organizational Unit (OU) for the certificate/CSR
#   --email <string>            Email address for the user certificate/CSR
#   --alt_names_DNS <string>    SAN DNS entries for the certificate/CSR (separated by ; and wrappend in ")
#   --alt_names_URI <string>    SAN URI entries for the certificate/CSR (separated by ; and wrappend in ")
#   --alt_names_IP <string>     SAN IP entries for the certificate/CSR (separated by ; and wrappend in ")
#   --alt_names_email <string>  SAN Email entries for the certificate/CSR (separated by ; and wrappend in ")
#   --validity <days>           Validity period in days (default: 365)
#   --CA_cert                   Create a cert that can sign new certs (deafault is entity cert/CSR)
#   --self_signed_cert          Create a self-signed certificate (default: false)
#   --human_cert                Certificate identifies a human person instead of a machine (default: off)
#
# Secure Element:
#   When using a secure element for key storage, you have to supply the PKCS#11 key labels using the arguments
#   "--issuerKey", "--issuerAltKey", "--entityKey" and "--entityAltKey" prepending the string
#   "pkcs11:" followed by the key label.
#   You can specify different PKCS#11 modules for the issuer and entity keys. For each, an individual slot
#   number and User PIN can be specified. If no slot is given, the first available slot is used.
#   --p11_issuer_module <path>  Path to the PKCS#11 module containing the issuer key
#   --p11_issuer_slot <id>      Slot id of the PKCS#11 module for the issuer key
#   --p11_issuer_pin <pin>      PIN for the PKCS#11 module containing the issuer key
#   --p11_entity_module <path>  Path to the PKCS#11 module containing the entity key
#   --p11_entity_slot <id>      Slot id of the PKCS#11 module for the entity key
#   --p11_entity_pin <pin>      PIN for the PKCS#11 module containing the entity key
#
# General:
#   --verbose                   Enable verbose output
#   --debug                     Enable debug output
#   --help                      Print this help

_kritis3m_pki_completions() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD - 1]}"

    opts="--issuer_key --issuer_alt_key --entity_key --entity_alt_key --issuer_cert --csr_in \
          --gen_key --gen_alt_key \
          --cert_out --csr_out --key_out --alt_key_out \
          --common_name --country --state --org --unit --email --alt_names_DNS --alt_names_URI --alt_names_IP --alt_names_email --validity --CA_cert --self_signed_cert --human_cert \
          --p11_issuer_module --p11_issuer_slot --p11_issuer_pin --p11_entity_module --p11_entity_slot --p11_entity_pin \
          --verbose --debug --help"

    case "${prev}" in
    --issuer_key | --issuer_alt_key | --entity_key | --entity_alt_key | --issuer_cert | --csr_in | --cert_out | --csr_out | --key_out | --alt_key_out | \
        --p11_issuer_module | --p11_entity_module)
        _filedir
        return 0
        ;;
    --common_name | --country | --state | --org | --unit | --email | --alt_names_DNS | --alt_names_URI | --alt_names_IP | --alt_names_email | --validity | --p11_issuer_slot | --p11_issuer_pin | \
        --p11_entity_slot | --p11_entity_pin)
        # No file completion needed for these options, just suggest an empty list
        COMPREPLY=()
        return 0
        ;;
    --gen_key | --gen_alt_key)
        algos="rsa2048 rsa3072 rsa4096 secp256 secp384 secp521 ed22519 ed448 mldsa44 mldsa65 mldsa87 falcon512 falcon1024"
        COMPREPLY=($(compgen -W "${algos}" -- ${cur}))
        return 0
        ;;
    *)
        COMPREPLY=($(compgen -W "${opts}" -- ${cur}))
        return 0
        ;;
    esac
}

# Usage: kritis3m_se_importer [OPTIONS]
#
# File input:
#   --key <file>                      Path to the primary key (PEM)
#   --alt_key <file>                  Path to the alternative key (PEM)
#   --entity_cert <file>              Path to the entity cert (PEM)
#   --intermediate_cert <file>        Path to the intermediate cert (PEM)
#   --root_cert <file>                Path to the root cert (PEM)
#
# PKCS#11 labels:
#   --key_label <label>               Label of the primary key
#   --alt_key_label <label>           Label of the alternative key
#   --entity_cert_label <file>        Label of the entity certificate
#   --intermediate_cert_label <file>  Label of the intermediate certificate
#   --root_cert_label <file>          Label of the intermediate certificate
#
# Secure Element:
#   --module_path <file>              Path to the PKCS#11 module library
#   --slot <id>                       Slot id of the PKCS#11 token (default is first available)
#   --pin <pin>                       PIN for the PKCS#11 token
#
# General:
#   --verbose                         Enable verbose output
#   --debug                           Enable debug output
#   --help                            Print this help

_kritis3m_se_importer_completions() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD - 1]}"

    opts="--key --alt_key --entity_cert --intermediate_cert --root_cert --pre_shared_key \
          --key_label --alt_key_label --entity_cert_label --intermediate_cert_label --root_cert_label --pre_shared_key_label \
          --module_path --slot --pin \
          --verbose --debug --help"

    case "${prev}" in
    --key | --alt_key | --entity_cert | --intermediate_cert | --root_cert | --module_path)
        _filedir
        return 0
        ;;
    --slot | --pin | --key_label | --alt_key_label | --entity_cert_label | --intermediate_cert_label | --root_cert_label | \
        --pre_shared_key_label | --pre_shared_key)
        # No file completion needed for these options, just suggest an empty list
        COMPREPLY=()
        return 0
        ;;
    *)
        COMPREPLY=($(compgen -W "${opts}" -- ${cur}))
        return 0
        ;;
    esac
}

complete -F _kritis3m_pki_completions kritis3m_pki
complete -F _kritis3m_se_importer_completions kritis3m_se_importer
