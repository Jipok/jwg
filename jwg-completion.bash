# Bash completion for jwg
# Install: source /etc/bash_completion.d/jwg
# Or add to ~/.bashrc: source /path/to/jwg-completion.bash

_jwg_peers() {
    local db_path="$1"
    
    if [[ -n "$db_path" && "$db_path" != -* ]]; then
        sudo jwg --db "$db_path" list 2>/dev/null
    else
        sudo jwg list 2>/dev/null
    fi
}

_jwg() {
    local cur prev words cword
    _init_completion || return

    local commands="add del rm show"
    local flags="--ip --port --iface --endpoint --subnet --nat-iface --dns --client-allowed-ips --db --i1 --help"

    local prev="${COMP_WORDS[COMP_CWORD-1]}"
    local cur="${COMP_WORDS[COMP_CWORD]}"

    case "$prev" in
        --iface)
            COMPREPLY=( $(compgen -W "$(ls /sys/class/net/ 2>/dev/null)" -- "$cur") )
            return 0
            ;;
        --nat-iface)
            COMPREPLY=( $(compgen -W "$(ls /sys/class/net/ 2>/dev/null | grep -v '^lo$')" -- "$cur") )
            return 0
            ;;
        --db)
            _filedir
            return 0
            ;;
        --port|--endpoint|--subnet|--dns|--client-allowed-ips|--ip|--i1)
            return 0
            ;;
    esac

    local cmd=""
    local db_path=""
    local i=0

    for word in "${COMP_WORDS[@]}"; do
        if [[ "$word" == "add" || "$word" == "del" || "$word" == "rm" || "$word" == "show" ]]; then
            cmd="$word"
        elif [[ "$word" == "--db" ]]; then
            local next_i=$((i + 1))
            if [[ $next_i -lt ${#COMP_WORDS[@]} ]]; then
                db_path="${COMP_WORDS[$next_i]}"
            fi
        fi
        ((i++))
    done

    if [[ "$cur" == -* ]]; then
        COMPREPLY=( $(compgen -W "$flags" -- "$cur") )
        return 0
    fi

    if [[ -z "$cmd" ]]; then
        COMPREPLY=( $(compgen -W "$commands $flags" -- "$cur") )
        return 0
    fi

    case "$cmd" in
        del|rm|show)
            local peers
            peers=$(_jwg_peers "$db_path")
            COMPREPLY=( $(compgen -W "$peers" -- "$cur") )
            ;;
        add)
            ;;
    esac
}

complete -F _jwg jwg
