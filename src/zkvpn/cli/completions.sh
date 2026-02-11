# ZK-VPN bash/zsh completions
# Source this file for tab completion

_zkvpn_completions() {
    local cur prev words cword
    _init_completion || return

    # Main commands
    COMMANDS="connect disconnect status proofs config peer test version help"
    
    # Proofs subcommands
    PROOF_COMMANDS="list verify generate clear"
    
    # Config subcommands
    CONFIG_COMMANDS="show set reset export"
    
    # Peer subcommands
    PEER_COMMANDS="add remove list"
    
    # Test subcommands
    TEST_COMMANDS="leak speed zk all"
    
    # Options
    COMMON_OPTS="--help --debug"
    CONNECT_OPTS="--endpoint --pubkey --config"
    STATUS_OPTS="--watch --json"
    CONFIG_OPTS="--format --secrets"
    
    case $prev in
        zkvpn)
            COMPREPLY=($(compgen -W "$COMMANDS $COMMON_OPTS" -- "$cur"))
            ;;
        proofs)
            COMPREPLY=($(compgen -W "$PROOF_COMMANDS" -- "$cur"))
            ;;
        config)
            COMPREPLY=($(compgen -W "$CONFIG_COMMANDS" -- "$cur"))
            ;;
        peer)
            COMPREPLY=($(compgen -W "$PEER_COMMANDS" -- "$cur"))
            ;;
        test)
            COMPREPLY=($(compgen -W "$TEST_COMMANDS" -- "$cur"))
            ;;
        connect)
            COMPREPLY=($(compgen -W "$CONNECT_OPTS" -- "$cur"))
            ;;
        status)
            COMPREPLY=($(compgen -W "$STATUS_OPTS" -- "$cur"))
            ;;
        export)
            COMPREPLY=($(compgen -W "--format" -- "$cur"))
            ;;
        *)
            # Suggest peers from config
            if [[ "$prev" == "remove" ]] || [[ "$prev" == "add" ]]; then
                COMPREPLY=($(compgen -W "$(wg show peers 2>/dev/null)" -- "$cur"))
            fi
            ;;
    esac
}

complete -F _zkvpn_completions zkvpn
