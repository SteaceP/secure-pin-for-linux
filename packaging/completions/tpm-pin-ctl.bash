# Bash completion for tpm-pin-ctl

_tpm_pin_ctl_completions() {
    local cur prev words cword
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    local cmds="status enroll change-pin verify remove list doctor pam da-reset da-config config version help"
    local config_keys="digits_only min_length max_length disallow_simple_pins enable_login enable_lockscreen enable_sudo enable_polkit enable_keyring_unlock bind_pcr7 da_max_tries da_recovery_time da_lockout_recovery tcti_name data_dir"
    local bool_keys="digits_only disallow_simple_pins enable_login enable_lockscreen enable_sudo enable_polkit enable_keyring_unlock bind_pcr7"

    if [[ $COMP_CWORD -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "$cmds --version -V --help -h" -- "$cur") )
        return 0
    fi

    if [[ "$prev" == "--user" ]]; then
        COMPREPLY=( $(compgen -u -- "$cur") )
        return 0
    fi

    local subcmd="${COMP_WORDS[1]}"
    case "$subcmd" in
        status|doctor)
            COMPREPLY=( $(compgen -W "--json --user" -- "$cur") )
            return 0
            ;;
        enroll|change-pin)
            COMPREPLY=( $(compgen -W "--user --pin --password" -- "$cur") )
            return 0
            ;;
        verify)
            COMPREPLY=( $(compgen -W "--user --pin" -- "$cur") )
            return 0
            ;;
        remove)
            COMPREPLY=( $(compgen -W "--user" -- "$cur") )
            return 0
            ;;
        list)
            COMPREPLY=( $(compgen -W "--json" -- "$cur") )
            return 0
            ;;
        pam)
            if [[ $COMP_CWORD -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "enable disable status" -- "$cur") )
            elif [[ "${COMP_WORDS[2]}" == "disable" ]]; then
                COMPREPLY=( $(compgen -W "--uninstall" -- "$cur") )
            fi
            return 0
            ;;
        da-config)
            COMPREPLY=( $(compgen -W "--max-tries --recovery-sec --lockout-recovery" -- "$cur") )
            return 0
            ;;
        config)
            if [[ $COMP_CWORD -eq 2 ]]; then
                COMPREPLY=( $(compgen -W "list get set" -- "$cur") )
            elif [[ "${COMP_WORDS[2]}" == "list" ]]; then
                COMPREPLY=( $(compgen -W "--json" -- "$cur") )
            elif [[ $COMP_CWORD -eq 3 ]] && [[ "${COMP_WORDS[2]}" == "get" || "${COMP_WORDS[2]}" == "set" ]]; then
                COMPREPLY=( $(compgen -W "$config_keys" -- "$cur") )
            elif [[ $COMP_CWORD -eq 4 && "${COMP_WORDS[2]}" == "set" ]]; then
                local k
                for k in $bool_keys; do
                    if [[ "$prev" == "$k" ]]; then
                        COMPREPLY=( $(compgen -W "true false" -- "$cur") )
                        return 0
                    fi
                done
            fi
            return 0
            ;;
    esac
}

complete -F _tpm_pin_ctl_completions tpm-pin-ctl
