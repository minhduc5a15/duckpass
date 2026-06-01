_duckpass_completion() {  
    local cur prev words cword  
    _init_completion || return  
  
    COMPREPLY=()  
    local subcommands="list get delete generate export shell completion"  
      
    local i=1  
    local subcommand=""  
    while [ $i -lt $cword ]; do  
        local s="${words[i]}"  
        case "$s" in  

            list|get|delete|generate|export|shell)  
                subcommand="$s"  
                break  
                ;;  
        esac  
        i=$((i+1))  
    done  
  
    if [ -z "$subcommand" ]; then  
        if [[ "$cur" == -* ]]; then  
            COMPREPLY=( $(compgen -W "--help --version" -- "$cur") )  
        else  
            COMPREPLY=( $(compgen -W "$subcommands" -- "$cur") )  
        fi  
        return 0  
    fi  
  
    case "$subcommand" in  
        get|delete|list)  
            if type duckpass &>/dev/null; then  
                local services=$(DUCKPASS_MASTER_PASSWORD="$DUCKPASS_MASTER_PASSWORD" duckpass __list_services_raw 2>/dev/null)  
                COMPREPLY=( $(compgen -W "$services" -- "$cur") )  
            fi  
            return 0  
            ;;  
    esac  
}  
  
complete -F _duckpass_completion duckpass
