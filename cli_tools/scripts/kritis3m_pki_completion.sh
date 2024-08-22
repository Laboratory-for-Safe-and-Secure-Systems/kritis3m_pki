#!/bin/bash

# Help print:
#
# Usage: kritis3m_pki [OPTIONS]
# Arguments:
#
# Key input:
#   --issuerKey <file>      Path to the primary issuer key in PEM format
#   --issuerAltKey <file>   Path to the alternative issuer key in PEM format (generate hybrid cert)
#   --entityKey <file>      Path to the primary entity key in PEM format (same as issuerKey for self-signed cert)
#   --entityAltKey <file>   Path to the alternative entity key in PEM format (same as issuerAltKey for self-signed cert)
#
# Certificate/CSR input:
#   --issuerCert <file>     Path to the issuer certificate in PEM format
#   --csrIn <file>          Path to a CSR in PEM format
#
# Key generation:
#   Currently supported algorithms: rsa2048, rsa3072, rsa4096, secp256, secp384, secp521, mldsa44, mldsa65, mldsa87
#   --genKey <alogrithm>    Algorithm for key generation (see list above)
#   --genAltKey <alogrithm> Algorithm for alternative key generation (see list above)
#
# Output:
#   --certOut <file>        Path to the root certificate output file (PEM)
#   --csrOut <file>         Path to the CSR output file (PEM)
#   --keyOut <file>         Path to the primary key output file (PEM)
#   --altKeyOut <file>      Path to the alternative key output file (PEM)
#
# Metadata:
#   --CN <string>           Common Name (CN) for the certificate/CSR
#   --O <string>            Organization (O) for the certificate/CSR
#   --OU <string>           Organizational Unit (OU) for the certificate/CSR
#   --altNamesDNS <string>  SAN DNS entries for the certificate/CSR (separated by ; and wrappend in ")
#   --altNamesURI <string>  SAN URI entries for the certificate/CSR (separated by ; and wrappend in ")
#   --altNamesIP <string>   SAN IP address entries for the certificate/CSR (separated by ; and wrappend in ")
#   --validity <days>       Validity period in days (default: 365)
#   --enableCA              Create a cert that can sign new certs (deafault is entity cert/CSR)
#
# Secure Element:
#   When using a secure element for key storage, you have to supply the PKCS#11 key labels using the arguments
#   "--issuerKey", "--issuerAltKey", "--entityKey" and "--entityAltKey" prepending the string
#   "pkcs11:" followed by the key label.
#   --middleware <file>     Path to the secure element middleware
#   --slotIssuerKey <id>    Slot id of the secure element containing the issuer keys (default is first available)
#   --slotEntityKey <id>    Slot id of the secure element containing the entity keys (default is first available)
#
# General:
#   --verbose               Enable verbose output
#   --help                  Print this help

_kritis3m_pki_completions() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    opts="--issuerKey --issuerAltKey --entityKey --entityAltKey --issuerCert --csrIn \
          --genKey --genAltKey \
          --certOut --csrOut --keyOut --altKeyOut \
          --CN --O --OU --altNamesDNS --altNamesURI --altNamesIP --validity --enableCA \
          --middleware --slotIssuerKey --slotEntityKey \
          --verbose --help"

    case "${prev}" in
        --issuerKey|--issuerAltKey|--entityKey|--entityAltKey|--issuerCert|--csrIn|--certOut|--csrOut|--keyOut|--altKeyOut|--middleware)
            _filedir
            return 0
            ;;
        --CN|--O|--OU|--altNamesDNS|--altNamesURI|--altNamesIP|--validity|--slotIssuerKey|--slotEntityKey)
            # No file completion needed for these options, just suggest an empty list
            COMPREPLY=()
            return 0
            ;;
        --genKey|--genAltKey)
            algos="rsa2048 rsa3072 rsa4096 secp256 secp384 secp521 mldsa44 mldsa65 mldsa87"
            COMPREPLY=( $(compgen -W "${algos}" -- ${cur}) )
            return 0
            ;;
        *)
            COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
            return 0
            ;;
    esac
}

complete -F _kritis3m_pki_completions kritis3m_pki
