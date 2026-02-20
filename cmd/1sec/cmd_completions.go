package main

// ---------------------------------------------------------------------------
// cmd_completions.go — shell completion scripts
// ---------------------------------------------------------------------------

import (
	"fmt"
	"os"
	"strings"
)

func cmdCompletions(args []string) {
	if len(args) == 0 {
		cmdHelp("completions")
		os.Exit(0)
	}

	shell := strings.ToLower(args[0])
	switch shell {
	case "bash":
		fmt.Print(bashCompletions())
	case "zsh":
		fmt.Print(zshCompletions())
	case "fish":
		fmt.Print(fishCompletions())
	case "powershell", "pwsh":
		fmt.Print(powershellCompletions())
	default:
		errorf("unsupported shell %q — supported: bash, zsh, fish, powershell", shell)
	}
}

func bashCompletions() string {
	return `# 1sec bash completions
# Add to ~/.bashrc: source <(1sec completions bash)

_1sec_completions() {
    local cur prev commands
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    commands="up stop status alerts scan modules config check logs events export profile dashboard init docker completions version help"

    case "${prev}" in
        1sec)
            COMPREPLY=( $(compgen -W "${commands}" -- "${cur}") )
            return 0
            ;;
        alerts)
            COMPREPLY=( $(compgen -W "ack resolve false-positive get clear --severity --module --status --limit --format --output" -- "${cur}") )
            return 0
            ;;
        modules)
            COMPREPLY=( $(compgen -W "info enable disable --format --tier" -- "${cur}") )
            return 0
            ;;
        config)
            COMPREPLY=( $(compgen -W "set --validate --format --output" -- "${cur}") )
            return 0
            ;;
        docker)
            COMPREPLY=( $(compgen -W "up down logs status build pull" -- "${cur}") )
            return 0
            ;;
        completions)
            COMPREPLY=( $(compgen -W "bash zsh fish powershell" -- "${cur}") )
            return 0
            ;;
        export)
            COMPREPLY=( $(compgen -W "--type --format --output --severity --module --limit" -- "${cur}") )
            return 0
            ;;
        profile)
            COMPREPLY=( $(compgen -W "list create show delete use" -- "${cur}") )
            return 0
            ;;
        help)
            COMPREPLY=( $(compgen -W "${commands}" -- "${cur}") )
            return 0
            ;;
        --severity)
            COMPREPLY=( $(compgen -W "INFO LOW MEDIUM HIGH CRITICAL" -- "${cur}") )
            return 0
            ;;
        --format)
            COMPREPLY=( $(compgen -W "table json csv sarif" -- "${cur}") )
            return 0
            ;;
        --module|info|enable|disable)
            local modules="network_guardian api_fortress iot_shield injection_shield supply_chain ransomware auth_fortress deepfake_shield identity_monitor llm_firewall ai_containment data_poisoning quantum_crypto runtime_watcher cloud_posture ai_analysis_engine"
            COMPREPLY=( $(compgen -W "${modules}" -- "${cur}") )
            return 0
            ;;
        --log-level)
            COMPREPLY=( $(compgen -W "debug info warn error" -- "${cur}") )
            return 0
            ;;
        --config|--output|--input|--compose-file|--env-file)
            COMPREPLY=( $(compgen -f -- "${cur}") )
            return 0
            ;;
    esac

    if [[ "${cur}" == -* ]]; then
        COMPREPLY=( $(compgen -W "--config --api-key --format --profile --output --host --port --timeout --help" -- "${cur}") )
        return 0
    fi
}

complete -F _1sec_completions 1sec
`
}

func zshCompletions() string {
	return `#compdef 1sec
# 1sec zsh completions
# Add to ~/.zshrc: source <(1sec completions zsh)

_1sec() {
    local -a commands
    commands=(
        'up:Start the 1SEC engine with all enabled modules'
        'stop:Gracefully stop a running instance'
        'status:Show status of a running 1SEC instance'
        'alerts:Fetch, acknowledge, resolve, or clear alerts'
        'scan:Submit a payload for on-demand analysis'
        'modules:List, inspect, enable, or disable defense modules'
        'config:Show, validate, or modify configuration'
        'check:Run pre-flight diagnostics'
        'logs:Fetch recent logs from a running instance'
        'events:Submit events to the bus'
        'export:Export alerts/events in bulk'
        'profile:Manage named configuration profiles'
        'dashboard:Launch a live TUI dashboard'
        'init:Generate a starter configuration file'
        'docker:Manage the 1SEC Docker deployment'
        'completions:Generate shell completion scripts'
        'version:Print version and build info'
        'help:Show help for a command'
    )

    _arguments -C \
        '1:command:->command' \
        '*::arg:->args'

    case "$state" in
        command)
            _describe 'command' commands
            ;;
        args)
            case "${words[1]}" in
                alerts)
                    local -a alert_cmds
                    alert_cmds=('ack:Acknowledge an alert' 'resolve:Resolve an alert' 'false-positive:Mark as false positive' 'get:Get alert by ID' 'clear:Clear all alerts')
                    _describe 'subcommand' alert_cmds
                    ;;
                modules)
                    local -a mod_cmds
                    mod_cmds=('info:Show module details' 'enable:Enable a module' 'disable:Disable a module')
                    _describe 'subcommand' mod_cmds
                    ;;
                config)
                    local -a cfg_cmds
                    cfg_cmds=('set:Set a config value')
                    _describe 'subcommand' cfg_cmds
                    ;;
                docker)
                    local -a docker_cmds
                    docker_cmds=('up:Start containers' 'down:Stop containers' 'logs:View logs' 'status:Container status' 'build:Build image' 'pull:Pull image')
                    _describe 'subcommand' docker_cmds
                    ;;
                export)
                    _arguments '--type[Export type]:type:(alerts events)' '--format[Output format]:format:(json csv sarif)'
                    ;;
                profile)
                    local -a prof_cmds
                    prof_cmds=('list:List profiles' 'create:Create a profile' 'show:Show profile details' 'delete:Delete a profile' 'use:Set default profile')
                    _describe 'subcommand' prof_cmds
                    ;;
                completions)
                    _values 'shell' bash zsh fish powershell
                    ;;
                help)
                    _describe 'command' commands
                    ;;
            esac
            ;;
    esac
}

_1sec "$@"
`
}

func fishCompletions() string {
	return `# 1sec fish completions
# Add: 1sec completions fish | source

complete -c 1sec -f

# Main commands
complete -c 1sec -n '__fish_use_subcommand' -a up -d 'Start the 1SEC engine'
complete -c 1sec -n '__fish_use_subcommand' -a stop -d 'Stop a running instance'
complete -c 1sec -n '__fish_use_subcommand' -a status -d 'Show instance status'
complete -c 1sec -n '__fish_use_subcommand' -a alerts -d 'Manage alerts'
complete -c 1sec -n '__fish_use_subcommand' -a scan -d 'Scan a payload'
complete -c 1sec -n '__fish_use_subcommand' -a modules -d 'Manage modules'
complete -c 1sec -n '__fish_use_subcommand' -a config -d 'Manage configuration'
complete -c 1sec -n '__fish_use_subcommand' -a check -d 'Pre-flight diagnostics'
complete -c 1sec -n '__fish_use_subcommand' -a logs -d 'Fetch logs'
complete -c 1sec -n '__fish_use_subcommand' -a events -d 'Submit events'
complete -c 1sec -n '__fish_use_subcommand' -a export -d 'Export alerts/events'
complete -c 1sec -n '__fish_use_subcommand' -a profile -d 'Manage profiles'
complete -c 1sec -n '__fish_use_subcommand' -a dashboard -d 'Live TUI dashboard'
complete -c 1sec -n '__fish_use_subcommand' -a init -d 'Generate config file'
complete -c 1sec -n '__fish_use_subcommand' -a docker -d 'Docker deployment'
complete -c 1sec -n '__fish_use_subcommand' -a completions -d 'Shell completions'
complete -c 1sec -n '__fish_use_subcommand' -a version -d 'Print version'
complete -c 1sec -n '__fish_use_subcommand' -a help -d 'Show help'

# alerts subcommands
complete -c 1sec -n '__fish_seen_subcommand_from alerts' -a ack -d 'Acknowledge alert'
complete -c 1sec -n '__fish_seen_subcommand_from alerts' -a resolve -d 'Resolve alert'
complete -c 1sec -n '__fish_seen_subcommand_from alerts' -a false-positive -d 'Mark false positive'
complete -c 1sec -n '__fish_seen_subcommand_from alerts' -a get -d 'Get alert by ID'
complete -c 1sec -n '__fish_seen_subcommand_from alerts' -a clear -d 'Clear all alerts'

# modules subcommands
complete -c 1sec -n '__fish_seen_subcommand_from modules' -a info -d 'Module details'
complete -c 1sec -n '__fish_seen_subcommand_from modules' -a enable -d 'Enable module'
complete -c 1sec -n '__fish_seen_subcommand_from modules' -a disable -d 'Disable module'

# docker subcommands
complete -c 1sec -n '__fish_seen_subcommand_from docker' -a 'up down logs status build pull'

# export subcommands
complete -c 1sec -n '__fish_seen_subcommand_from export' -l type -d 'Export type' -ra 'alerts events'
complete -c 1sec -n '__fish_seen_subcommand_from export' -l format -d 'Output format' -ra 'json csv sarif'

# profile subcommands
complete -c 1sec -n '__fish_seen_subcommand_from profile' -a 'list create show delete use'

# completions subcommands
complete -c 1sec -n '__fish_seen_subcommand_from completions' -a 'bash zsh fish powershell'

# Global flags
complete -c 1sec -l config -d 'Config file path' -r -F
complete -c 1sec -l api-key -d 'API key' -r
complete -c 1sec -l format -d 'Output format' -ra 'table json csv sarif'
complete -c 1sec -l profile -d 'Named profile' -r
complete -c 1sec -l output -d 'Output file' -r -F
complete -c 1sec -l host -d 'API host' -r
complete -c 1sec -l port -d 'API port' -r
complete -c 1sec -l timeout -d 'Request timeout' -r
complete -c 1sec -l help -d 'Show help'
`
}

func powershellCompletions() string {
	return `# 1sec PowerShell completions
# Add: 1sec completions powershell | Out-String | Invoke-Expression

Register-ArgumentCompleter -Native -CommandName 1sec -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)

    $commands = @{
        'up' = 'Start the 1SEC engine'
        'stop' = 'Stop a running instance'
        'status' = 'Show instance status'
        'alerts' = 'Manage alerts'
        'scan' = 'Scan a payload'
        'modules' = 'Manage modules'
        'config' = 'Manage configuration'
        'check' = 'Pre-flight diagnostics'
        'logs' = 'Fetch logs'
        'events' = 'Submit events'
        'export' = 'Export alerts/events'
        'profile' = 'Manage profiles'
        'dashboard' = 'Live TUI dashboard'
        'init' = 'Generate config file'
        'docker' = 'Docker deployment'
        'completions' = 'Shell completions'
        'version' = 'Print version'
        'help' = 'Show help'
    }

    $elements = $commandAst.CommandElements
    $command = if ($elements.Count -gt 1) { $elements[1].Value } else { '' }

    if ($elements.Count -le 2) {
        $commands.GetEnumerator() | Where-Object { $_.Key -like "$wordToComplete*" } | ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_.Key, $_.Key, 'ParameterValue', $_.Value)
        }
    } else {
        switch ($command) {
            'alerts' {
                @('ack', 'resolve', 'false-positive', 'get', 'clear') | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                    [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
                }
            }
            'modules' {
                @('info', 'enable', 'disable') | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                    [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
                }
            }
            'docker' {
                @('up', 'down', 'logs', 'status', 'build', 'pull') | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                    [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
                }
            }
            'export' {
                @('--type', '--format', '--output', '--severity', '--module') | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                    [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
                }
            }
            'profile' {
                @('list', 'create', 'show', 'delete', 'use') | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                    [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
                }
            }
            'completions' {
                @('bash', 'zsh', 'fish', 'powershell') | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
                    [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
                }
            }
        }
    }
}
`
}
