#!/bin/bash

# Help print:
#
# Usage: kritis3m_se_importer [OPTIONS]
# Arguments:
#
# Key file input:
#   --key <file>             Path to the primary key in PEM format
#   --altKey <file>          Path to the alternative key in PEM format
#
# PKCS#11 key labels:
#   --keyLabel <label>       Label of the primary key in PKCS#11
#   --altKeyLabel <label>    Label of the alternative key in PKCS#11
#
# Secure Element:
#   --middleware <file>      Path to the secure element middleware
#   --slot <id>              Slot id of the secure element containing the issuer keys (default is first available)
#
# General:
#   --verbose               Enable verbose output
#   --help                  Print this help


_kritis3m_se_importer_completions() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    opts="--key --altKey \
          --keyLabel --altKeyLabel \
          --middleware --slot \
          --verbose --help"

    case "${prev}" in
        --key|--altKey|--middleware)
            _filedir
            return 0
            ;;
        --slot|--keyLabel|--altKeyLabel)
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

complete -F _kritis3m_se_importer_completions kritis3m_se_importer
