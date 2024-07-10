#!/bin/bash

_kritis3m_pki_completions() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    opts="--issuerKey --issuerAltKey --ownKey --ownAltKey --issuerCert --csrIn --certOut --csrOut --CN --O --OU --altName --validity --enableCA --verbose --help"

    case "${prev}" in
        --issuerKey|--issuerAltKey|--ownKey|--ownAltKey|--issuerCert|--csrIn|--certOut|--csrOut)
            _filedir
            return 0
            ;;
        --CN|--O|--OU|--altName|--validity)
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
