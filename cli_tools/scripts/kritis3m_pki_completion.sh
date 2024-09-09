#!/bin/bash

# Help prints:
#
# Usage: kritis3m_pki [OPTIONS]
#
# Key input:
#   --issuer_key <file>           Path to the primary issuer key in PEM format
#   --issuer_alt_key <file>       Path to the alternative issuer key in PEM format (generate hybrid cert)
#   --entity_key <file>           Path to the primary entity key in PEM format (same as issuerKey for self-signed cert)
#   --entity_alt_key <file>       Path to the alternative entity key in PEM format (same as issuerAltKey for self-signed cert)
#
# Certificate/CSR input:
#   --issuer_cert <file>          Path to the issuer certificate in PEM format
#   --csr_in <file>               Path to a CSR in PEM format
#
# Key generation:
#   Currently supported algorithms: rsa2048, rsa3072, rsa4096
#                                   secp256, secp384, secp521
#                                   ed25519, ed448
#                                   mldsa44, mldsa65, mldsa87
#   --gen_key <alogrithm>         Algorithm for key generation (see list above)
#   --gen_alt_key <alogrithm>     Algorithm for alternative key generation (see list above)
#
# Output:
#   --cert_out <file>             Path to the root certificate output file (PEM)
#   --csr_out <file>              Path to the CSR output file (PEM)
#   --key_out <file>              Path to the primary key output file (PEM)
#   --alt_key_out <file>          Path to the alternative key output file (PEM)
#
# Metadata:
#   --common_name <string>        Common Name (CN) for the certificate/CSR
#   --country <string>            Country (C) for the certificate/CSR
#   --state <string>              State (ST) for the certificate/CSR
#   --org <string>                Organization (O) for the certificate/CSR
#   --unit <string>               Organizational Unit (OU) for the certificate/CSR
#   --alt_names_DNS <string>      SAN DNS entries for the certificate/CSR (separated by ; and wrappend in ")
#   --alt_names_URI <string>      SAN URI entries for the certificate/CSR (separated by ; and wrappend in ")
#   --alt_names_IP <string>       SAN IP address entries for the certificate/CSR (separated by ; and wrappend in ")
#   --validity <days>             Validity period in days (default: 365)
#   --CA_cert                     Create a cert that can sign new certs (deafault is entity cert/CSR)
#   --self_signed_cert            Create a self-signed certificate (default: false)
#
# Secure Element:
#   When using a secure element for key storage, you have to supply the PKCS#11 key labels using the arguments
#   "--issuerKey", "--issuerAltKey", "--entityKey" and "--entityAltKey" prepending the string
#   "pkcs11:" followed by the key label.
#   --middleware <file>           Path to the secure element middleware
#   --slot_issuer_key <id>        Slot id of the secure element containing the issuer keys (default is first available)
#   --slot_entity_key <id>        Slot id of the secure element containing the entity keys (default is first available)
#
# General:
#   --verbose                     Enable verbose output
#   --debug                       Enable debug output
#   --help                        Print this help

_kritis3m_pki_completions() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    opts="--issuer_key --issuer_alt_key --entity_key --entity_alt_key --issuer_cert --csr_in \
          --gen_key --gen_alt_key \
          --cert_out --csr_out --key_out --alt_key_out \
          --common_name --country --state --org --unit --alt_names_DNS --alt_names_URI --alt_names_IP --validity --CA_cert --self_signed_cert \
          --middleware --slot_issuer_key --slot_entity_key \
          --verbose --debug --help"

    case "${prev}" in
        --issuer_key|--issuer_alt_key|--entity_key|--entity_alt_key|--issuer_cert|--csr_in|--cert_out|--csr_out|--key_out|--alt_key_out|--middleware)
            _filedir
            return 0
            ;;
        --common_name|--country|--state|--org|--unit|--alt_names_DNS|--alt_names_URI|--alt_names_IP|--validity|--slot_issuer_key|--slot_entity_key)
            # No file completion needed for these options, just suggest an empty list
            COMPREPLY=()
            return 0
            ;;
        --gen_key|--gen_alt_key)
            algos="rsa2048 rsa3072 rsa4096 secp256 secp384 secp521 ed22519 ed448 mldsa44 mldsa65 mldsa87"
            COMPREPLY=( $(compgen -W "${algos}" -- ${cur}) )
            return 0
            ;;
        *)
            COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
            return 0
            ;;
    esac
}


# Usage: kritis3m_se_importer [OPTIONS]
#
# Key file input:
#   --key <file>                  Path to the primary key in PEM format
#   --alt_key <file>              Path to the alternative key in PEM format
#
# PKCS#11 key labels:
#   --key_label <label>           Label of the primary key in PKCS#11
#   --alt_key_label <label>       Label of the alternative key in PKCS#11
#
# Secure Element:
#   --middleware <file>           Path to the secure element middleware
#   --slot <id>                   Slot id of the secure element containing the issuer keys (default is first available)
#
# General:
#   --verbose                     Enable verbose output
#   --debug                       Enable debug output
#   --help                        Print this help

_kritis3m_se_importer_completions() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    opts="--key --alt_key \
          --key_label --alt_key_label \
          --middleware --slot \
          --verbose --debug --help"

    case "${prev}" in
        --key|--alt_key|--middleware)
            _filedir
            return 0
            ;;
        --slot|--key_label|--alt_key_label)
            # No file completion needed for these options, just suggest an empty list
            COMPREPLY=()
            return 0
            ;;
        *)
            COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
            return 0
            ;;
    esac
}


complete -F _kritis3m_pki_completions kritis3m_pki
complete -F _kritis3m_se_importer_completions kritis3m_se_importer
