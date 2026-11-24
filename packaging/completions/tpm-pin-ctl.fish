# Fish completions for tpm-pin-ctl

set -l tpm_pin_cmds status enroll change-pin verify remove list doctor pam da-reset da-config config version help
set -l tpm_pin_keys digits_only min_length max_length disallow_simple_pins enable_login enable_lockscreen enable_sudo enable_polkit enable_keyring_unlock bind_pcr7 da_max_tries da_recovery_time da_lockout_recovery tcti_name data_dir
set -l tpm_pin_bool_keys digits_only disallow_simple_pins enable_login enable_lockscreen enable_sudo enable_polkit enable_keyring_unlock bind_pcr7

complete -c tpm-pin-ctl -f
complete -c tpm-pin-ctl -n "not __fish_seen_subcommand_from $tpm_pin_cmds" -a status -d "Show TPM and PIN status"
complete -c tpm-pin-ctl -n "not __fish_seen_subcommand_from $tpm_pin_cmds" -a enroll -d "Enroll or re-enroll a PIN"
complete -c tpm-pin-ctl -n "not __fish_seen_subcommand_from $tpm_pin_cmds" -a change-pin -d "Rotate an existing PIN"
complete -c tpm-pin-ctl -n "not __fish_seen_subcommand_from $tpm_pin_cmds" -a verify -d "Verify a PIN against TPM"
complete -c tpm-pin-ctl -n "not __fish_seen_subcommand_from $tpm_pin_cmds" -a remove -d "Remove an enrolled PIN"
complete -c tpm-pin-ctl -n "not __fish_seen_subcommand_from $tpm_pin_cmds" -a list -d "List enrolled users"
complete -c tpm-pin-ctl -n "not __fish_seen_subcommand_from $tpm_pin_cmds" -a doctor -d "Run system health diagnostics"
complete -c tpm-pin-ctl -n "not __fish_seen_subcommand_from $tpm_pin_cmds" -a pam -d "Manage PAM integration"
complete -c tpm-pin-ctl -n "not __fish_seen_subcommand_from $tpm_pin_cmds" -a da-reset -d "Reset TPM DA lockout counter"
complete -c tpm-pin-ctl -n "not __fish_seen_subcommand_from $tpm_pin_cmds" -a da-config -d "Configure TPM DA protection"
complete -c tpm-pin-ctl -n "not __fish_seen_subcommand_from $tpm_pin_cmds" -a config -d "Get, set, or list configuration"
complete -c tpm-pin-ctl -n "not __fish_seen_subcommand_from $tpm_pin_cmds" -a version -d "Show version"
complete -c tpm-pin-ctl -n "not __fish_seen_subcommand_from $tpm_pin_cmds" -s V -l version -d "Show version"
complete -c tpm-pin-ctl -n "not __fish_seen_subcommand_from $tpm_pin_cmds" -s h -l help -d "Show help"

complete -c tpm-pin-ctl -n "__fish_seen_subcommand_from status doctor list" -l json -d "Output JSON"
complete -c tpm-pin-ctl -n "__fish_seen_subcommand_from status enroll change-pin verify remove doctor" -l user -r -a "(__fish_complete_users)" -d "Target username"
complete -c tpm-pin-ctl -n "__fish_seen_subcommand_from pam" -n "not __fish_seen_subcommand_from enable disable status" -a "enable disable status"
complete -c tpm-pin-ctl -n "__fish_seen_subcommand_from pam" -n "__fish_seen_subcommand_from disable" -l uninstall -d "Clean uninstall mode"
complete -c tpm-pin-ctl -n "__fish_seen_subcommand_from da-config" -l max-tries -r -d "Max failed attempts"
complete -c tpm-pin-ctl -n "__fish_seen_subcommand_from da-config" -l recovery-sec -r -d "Cooldown recovery seconds"
complete -c tpm-pin-ctl -n "__fish_seen_subcommand_from da-config" -l lockout-recovery -r -d "Lockout recovery seconds"
complete -c tpm-pin-ctl -n "__fish_seen_subcommand_from config" -n "not __fish_seen_subcommand_from list get set" -a "list get set"
complete -c tpm-pin-ctl -n "__fish_seen_subcommand_from config" -n "__fish_seen_subcommand_from list" -l json -d "Output JSON"
complete -c tpm-pin-ctl -n "__fish_seen_subcommand_from config" -n "__fish_seen_subcommand_from get set" -n "not __fish_seen_subcommand_from $tpm_pin_keys" -a "$tpm_pin_keys"
complete -c tpm-pin-ctl -n "__fish_seen_subcommand_from config" -n "__fish_seen_subcommand_from set" -n "__fish_seen_subcommand_from $tpm_pin_bool_keys" -a "true false"
