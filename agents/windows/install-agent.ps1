<#
.SYNOPSIS
    Reefed - instala e registra o agente do Wazuh num servidor Windows.

.DESCRIPTION
    Rode num PowerShell aberto como administrador.

    Servidor comum:
        .\install-agent.ps1 -Manager 10.0.0.10 -Password SENHA

    Servidor de banco (escolha o banco):
        .\install-agent.ps1 -Manager 10.0.0.10 -Password SENHA -Database postgresql

    Se a política de execução bloquear o script:
        powershell -ExecutionPolicy Bypass -File .\install-agent.ps1 -Manager 10.0.0.10 -Password SENHA

    O que o script faz:
      - baixa o MSI oficial do Wazuh, confere a assinatura digital, instala e registra
        o agente nos grupos do Reefed (windows, ou windows,database,<banco> com -Database);
      - liga o log de conexões bloqueadas do firewall do Windows (pfirewall.log), lido
        pelo grupo "windows", e avisa se algum perfil do firewall estiver desligado: o
        Active Response bloqueia IPs com uma regra do firewall (netsh);
      - liga a auditoria de logon, de contas e grupos e de mudanças de política, que
        alimenta as regras de login do Windows (eventos 4624, 4625, 4720, 4732...);
      - tira ".log$" da lista de arquivos ignorados pelo FIM, para o Reefed saber quando
        alguém apaga um log do banco (regra 110804);
      - em servidor de banco, descobre a instalação pelo serviço do Windows e grava no
        ossec.conf do agente os caminhos dos logs e dos arquivos monitorados pelo FIM.
        No MySQL/MariaDB acrescenta a verificação de skip-grant-tables (regra 110056).
        Os caminhos dependem da versão instalada, por isso ficam no agente e não na
        configuração central do grupo. Depois de atualizar o banco, rode de novo com
        -ConfigureOnly.

    O script não muda a configuração do banco. Ele confere e mostra o que falta
    (veja agents/database/ e docs/agentes.md).

.PARAMETER Manager
    Endereço (IP ou nome) do servidor do Reefed. Obrigatório, menos com -ConfigureOnly.

.PARAMETER Password
    Senha de registro de agentes: REEFED_ENROLLMENT_PASSWORD do .env do servidor.

.PARAMETER Name
    Nome do agente. Padrão: nome do computador.

.PARAMETER Groups
    Grupos do agente. Padrão: windows, ou windows,database,<banco> com -Database.

.PARAMETER Database
    postgresql, mysql ou mariadb: servidor de banco.

.PARAMETER DatabaseService
    Nome do serviço do Windows do banco, se houver mais de um ou se o script não achar.

.PARAMETER Version
    Versão do agente (padrão 4.14.9). Não pode ser maior que a do servidor do Reefed.

.PARAMETER MsiPath
    MSI do agente já baixado, para servidor sem acesso à internet.

.PARAMETER SkipSignatureCheck
    Não confere a assinatura digital do MSI. Use só com um arquivo de origem conhecida.

.PARAMETER NoFirewall
    Não mexe no log do firewall do Windows.

.PARAMETER NoAuditPolicy
    Não mexe na política de auditoria (por exemplo, quando ela vem de uma GPO do domínio).

.PARAMETER FlagsInterval
    Segundos entre as verificações de skip-grant-tables (padrão 300).

.PARAMETER ConfigureOnly
    Não instala nem registra: só aplica os ajustes do Reefed e reinicia o agente.

.EXAMPLE
    .\install-agent.ps1 -Manager reefed.empresa.local -Password SENHA -Database mysql

.EXAMPLE
    .\install-agent.ps1 -ConfigureOnly -Database postgresql
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', 'Password',
    Justification = 'A senha de registro vai para o msiexec e o agent-auth como texto, que é o que eles aceitam.')]
[CmdletBinding()]
param(
    [string]$Manager,
    [string]$Password,
    [string]$Name = $env:COMPUTERNAME,
    [string]$Groups,
    [ValidateSet('postgresql', 'mysql', 'mariadb')]
    [string]$Database,
    [string]$DatabaseService,
    [ValidatePattern('^\d+\.\d+\.\d+$')]
    [string]$Version = '4.14.9',
    [string]$MsiPath,
    [switch]$SkipSignatureCheck,
    [switch]$NoFirewall,
    [switch]$NoAuditPolicy,
    [ValidateRange(60, 86400)]
    [int]$FlagsInterval = 300,
    [switch]$ConfigureOnly
)

$LocalBegin = '<!-- REEFED-LOCAL-BEGIN: gerado pelo install-agent.ps1 do Reefed -->'
$LocalEnd = '<!-- REEFED-LOCAL-END -->'
$FirewallLog = '%systemroot%\system32\LogFiles\Firewall\pfirewall.log'
$PgLinePrefix = '%m [%p] user=%u db=%d client=%h app=%a '

# Subcategorias de auditoria pelo GUID: os nomes mudam com o idioma do Windows
$AuditSubcategories = [ordered]@{
    '{0CCE923F-69AE-11D9-BED3-505054503030}' = 'validação de credenciais'
    '{0CCE9215-69AE-11D9-BED3-505054503030}' = 'logon'
    '{0CCE9217-69AE-11D9-BED3-505054503030}' = 'bloqueio de conta'
    '{0CCE921B-69AE-11D9-BED3-505054503030}' = 'logon especial'
    '{0CCE9235-69AE-11D9-BED3-505054503030}' = 'contas de usuário'
    '{0CCE9237-69AE-11D9-BED3-505054503030}' = 'grupos de segurança'
    '{0CCE922F-69AE-11D9-BED3-505054503030}' = 'política de auditoria'
    '{0CCE9232-69AE-11D9-BED3-505054503030}' = 'regras do firewall'
}

# ---------------------------------------------------------------------------
# Mensagens

function Write-ReefedInfo([string]$Message) {
    Write-Host '[reefed] ' -ForegroundColor Cyan -NoNewline
    Write-Host $Message
}

function Write-ReefedWarning([string]$Message) {
    Write-Host '[reefed] ' -ForegroundColor Yellow -NoNewline
    Write-Host $Message -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# Funções sem efeito colateral (testadas em tests/windows/test-install-agent.ps1)

function Split-CommandLine([string]$CommandLine) {
    # Separa a linha de comando de um serviço como o Windows faz: aspas agrupam
    $tokens = New-Object System.Collections.Generic.List[string]
    $current = New-Object System.Text.StringBuilder
    $inQuotes = $false
    $hasToken = $false
    foreach ($ch in "$CommandLine".ToCharArray()) {
        if ($ch -eq '"') {
            $inQuotes = -not $inQuotes
            $hasToken = $true
        } elseif (-not $inQuotes -and [char]::IsWhiteSpace($ch)) {
            if ($hasToken) {
                $tokens.Add($current.ToString())
                [void]$current.Clear()
                $hasToken = $false
            }
        } else {
            [void]$current.Append($ch)
            $hasToken = $true
        }
    }
    if ($hasToken) { $tokens.Add($current.ToString()) }
    $tokens.ToArray()
}

function Get-ParentPath([string]$Path) {
    $trimmed = $Path.TrimEnd('\')
    $index = $trimmed.LastIndexOf('\')
    if ($index -le 0) { return $trimmed }
    $trimmed.Substring(0, $index)
}

function Resolve-DbPath([string]$Value, [string]$Base) {
    # Caminho de um arquivo de configuração do banco: aceita / e \\, relativo ao $Base
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    $path = $Value.Trim().Trim('"', "'") -replace '\\\\', '\' -replace '/', '\'
    if ($path -match '^[A-Za-z]:\\' -or $path.StartsWith('\\')) { return $path.TrimEnd('\') }
    if ($path.StartsWith('.\')) { $path = $path.Substring(2) }
    $Base.TrimEnd('\') + '\' + $path.TrimStart('\').TrimEnd('\')
}

function Remove-InlineComment([string]$Value, [string]$Markers) {
    # Tira o comentário do fim da linha, sem mexer no que está entre aspas
    $quote = $null
    for ($i = 0; $i -lt $Value.Length; $i++) {
        $ch = $Value[$i]
        if ($quote) {
            if ($ch -eq $quote) { $quote = $null }
        } elseif ($ch -eq "'" -or $ch -eq '"') {
            $quote = $ch
        } elseif ($Markers.IndexOf($ch) -ge 0 -and ($i -eq 0 -or [char]::IsWhiteSpace($Value[$i - 1]))) {
            return $Value.Substring(0, $i).Trim()
        }
    }
    $Value.Trim()
}

function Read-IniSetting([string[]]$Lines, [string]$SectionPattern) {
    # Opções do servidor no my.ini (seções [mysqld], [mariadb], [server]...).
    # Os nomes ficam em minúsculas e com _ no lugar de -. Opção sem valor fica ''.
    $settings = @{}
    $active = $false
    foreach ($raw in $Lines) {
        $line = "$raw".Trim()
        if ($line -eq '' -or $line -match '^[#;!]') { continue }
        if ($line -match '^\[(.+)\]$') {
            $active = $Matches[1].Trim() -match $SectionPattern
            continue
        }
        if (-not $active) { continue }
        if ($line -match '^([A-Za-z0-9_.-]+)\s*(?:=(.*))?$') {
            $key = $Matches[1].ToLowerInvariant().Replace('-', '_')
            $value = ''
            if ($null -ne $Matches[2]) { $value = (Remove-InlineComment $Matches[2] '#').Trim('"', "'") }
            $settings[$key] = $value
        }
    }
    $settings
}

function Read-PgSetting([string[]]$Lines) {
    # Linhas "nome = valor" do postgresql.conf, na ordem (os includes vêm junto)
    foreach ($raw in $Lines) {
        $line = Remove-InlineComment "$raw" '#'
        if ($line -match '^([A-Za-z_][A-Za-z0-9_.]*)\s*=?\s*(.*)$') {
            $value = $Matches[2].Trim()
            if ($value.Length -ge 2 -and $value.StartsWith("'") -and $value.EndsWith("'")) {
                $value = $value.Substring(1, $value.Length - 2).Replace("''", "'")
            }
            [pscustomobject]@{ Name = $Matches[1].ToLowerInvariant(); Value = $value }
        }
    }
}

function Test-OptionOn([hashtable]$Settings, [string]$Key) {
    $Settings.ContainsKey($Key) -and $Settings[$Key] -match '^(|1|on|true|yes|force|force_plus_permanent)$'
}

function Get-PostgresLayout([string]$PathName, [scriptblock]$ReadFile) {
    $tokens = @(Split-CommandLine $PathName)
    $binDir = Get-ParentPath $tokens[0]
    $installDir = Get-ParentPath $binDir
    $dataDir = $null
    for ($i = 1; $i -lt $tokens.Count; $i++) {
        if ($tokens[$i] -ceq '-D' -and $i + 1 -lt $tokens.Count) { $dataDir = $tokens[$i + 1] }
        elseif ($tokens[$i] -like '--pgdata=*') { $dataDir = $tokens[$i].Substring(9) }
        elseif ($tokens[$i] -cmatch '^-D.') { $dataDir = $tokens[$i].Substring(2) }
    }
    if (-not $dataDir) { return $null }
    $dataDir = Resolve-DbPath $dataDir $installDir

    # postgresql.conf com os includes, e por último o postgresql.auto.conf (ALTER SYSTEM)
    $settings = @{}
    $pending = New-Object System.Collections.Generic.Queue[string]
    $pending.Enqueue("$dataDir\postgresql.conf")
    $seen = @{}
    while ($pending.Count -gt 0) {
        $file = $pending.Dequeue()
        if ($seen.ContainsKey($file.ToLowerInvariant())) { continue }
        $seen[$file.ToLowerInvariant()] = $true
        foreach ($item in @(Read-PgSetting @(& $ReadFile $file))) {
            if ($item.Name -eq 'include' -or $item.Name -eq 'include_if_exists') {
                $pending.Enqueue((Resolve-DbPath $item.Value (Get-ParentPath $file)))
            } else {
                $settings[$item.Name] = $item.Value
            }
        }
    }
    foreach ($item in @(Read-PgSetting @(& $ReadFile "$dataDir\postgresql.auto.conf"))) { $settings[$item.Name] = $item.Value }

    $logDirectory = 'log'
    if ($settings.ContainsKey('log_directory')) { $logDirectory = $settings['log_directory'] }
    $logFilename = 'postgresql-%Y-%m-%d_%H%M%S.log'
    if ($settings.ContainsKey('log_filename')) { $logFilename = $settings['log_filename'] }
    # Padrão do strftime vira curinga: postgresql-%Y-%m-%d_%H%M%S.log -> postgresql-*.log
    $first = $logFilename.IndexOf('%')
    $last = $logFilename.LastIndexOf('%')
    $logPattern = $logFilename
    if ($first -ge 0) { $logPattern = $logFilename.Substring(0, $first) + '*' + $logFilename.Substring([Math]::Min($last + 2, $logFilename.Length)) }

    $missing = New-Object System.Collections.Generic.List[string]
    if ($settings['log_line_prefix'] -ne $PgLinePrefix) { $missing.Add("log_line_prefix = '$PgLinePrefix'") }
    if (-not (Test-OptionOn $settings 'logging_collector')) { $missing.Add('logging_collector = on') }
    if ($settings.ContainsKey('log_destination') -and $settings['log_destination'] -notmatch '(?i)stderr') { $missing.Add("log_destination = 'stderr'") }
    if (-not (Test-OptionOn $settings 'log_connections')) { $missing.Add('log_connections = on') }
    if (-not (Test-OptionOn $settings 'log_disconnections')) { $missing.Add('log_disconnections = on') }
    if ($settings['log_statement'] -notmatch '^(all|mod|ddl)$') { $missing.Add("log_statement = 'all'") }

    [pscustomobject]@{
        Db         = 'postgresql'
        InstallDir = $installDir
        BinDir     = $binDir
        DataDir    = $dataDir
        LogDir     = Resolve-DbPath $logDirectory $dataDir
        LogPattern = $logPattern
        Missing    = $missing.ToArray()
    }
}

function Get-MySqlLayout([string]$Db, [string]$PathName, [scriptblock]$ReadFile, [string]$HostName, [string]$WindowsDir) {
    $tokens = @(Split-CommandLine $PathName)
    $binDir = Get-ParentPath $tokens[0]
    $installDir = Get-ParentPath $binDir
    # Com --defaults-file o servidor lê só esse arquivo; sem ele, a lista padrão do Windows
    $configFiles = @("$WindowsDir\my.ini", "$WindowsDir\my.cnf", 'C:\my.ini', 'C:\my.cnf', "$installDir\my.ini", "$installDir\my.cnf")
    foreach ($token in $tokens) {
        if ($token -like '--defaults-file=*') { $configFiles = @(Resolve-DbPath $token.Substring(16) $installDir) }
    }
    $lines = New-Object System.Collections.Generic.List[string]
    $found = New-Object System.Collections.Generic.List[string]
    foreach ($file in $configFiles) {
        $content = @(& $ReadFile $file)
        if ($content.Count -gt 0) {
            $found.Add($file)
            foreach ($line in $content) { $lines.Add("$line") }
        }
    }
    $settings = Read-IniSetting $lines.ToArray() '^(mysqld|server|mariadb|mariadbd)(-[0-9.]+)?$'

    $dataDir = Resolve-DbPath $settings['datadir'] $installDir
    if (-not $dataDir) { $dataDir = "$installDir\data" }
    $pluginDir = Resolve-DbPath $settings['plugin_dir'] $installDir
    if (-not $pluginDir) { $pluginDir = "$installDir\lib\plugin" }
    $missing = New-Object System.Collections.Generic.List[string]
    $logs = [ordered]@{}

    if ($Db -eq 'mysql') {
        # Sem caminho, o MySQL grava na pasta de dados com o nome do computador
        $errorLog = Resolve-DbPath $settings['log_error'] $dataDir
        if (-not $errorLog) { $errorLog = "$dataDir\$HostName.err" }
        elseif ($errorLog.Substring($errorLog.LastIndexOf('\') + 1) -notmatch '\.') { $errorLog += '.err' }
        $slowLog = Resolve-DbPath $settings['slow_query_log_file'] $dataDir
        if (-not $slowLog) { $slowLog = "$dataDir\$HostName-slow.log" }
        $generalLog = Resolve-DbPath $settings['general_log_file'] $dataDir
        if (-not $generalLog) { $generalLog = "$dataDir\$HostName.log" }
        $logs['error'] = $errorLog
        $logs['slow'] = $slowLog
        $logs['general'] = $generalLog

        if ($settings['log_error_verbosity'] -ne '3') { $missing.Add('log_error_verbosity = 3') }
        if (-not (Test-OptionOn $settings 'slow_query_log')) { $missing.Add('slow_query_log = ON') }
        if ("$($settings['long_query_time'])" -notmatch '^0+(\.0*)?$') { $missing.Add('long_query_time = 0') }
        if (-not (Test-OptionOn $settings 'log_slow_extra')) { $missing.Add('log_slow_extra = ON') }
        if (-not (Test-OptionOn $settings 'log_slow_admin_statements')) { $missing.Add('log_slow_admin_statements = ON') }
        if (-not (Test-OptionOn $settings 'general_log')) { $missing.Add('general_log = ON') }
        if ($settings.ContainsKey('log_output') -and $settings['log_output'] -notmatch '(?i)file') { $missing.Add('log_output = FILE') }
    } else {
        $auditLog = Resolve-DbPath $settings['server_audit_file_path'] $dataDir
        if (-not $auditLog) { $auditLog = "$dataDir\server_audit.log" }
        elseif ($settings['server_audit_file_path'] -match '[\\/]$') { $auditLog += '\server_audit.log' }
        $logs['audit'] = $auditLog

        $plugins = "$($settings['plugin_load_add']);$($settings['plugin_load'])"
        if ($plugins -notmatch '(?i)server_audit') { $missing.Add('plugin_load_add = server_audit') }
        if ($settings['server_audit'] -notmatch '(?i)^force') { $missing.Add('server_audit = FORCE_PLUS_PERMANENT') }
        if (-not (Test-OptionOn $settings 'server_audit_logging')) { $missing.Add('server_audit_logging = ON') }
        # Sem server_audit_events o plugin registra todos os eventos, o que também serve
        $events = "$($settings['server_audit_events'])"
        if ($events -and ($events -notmatch '(?i)connect' -or $events -notmatch '(?i)query')) { $missing.Add('server_audit_events = CONNECT,QUERY,TABLE') }
        if ($settings.ContainsKey('server_audit_output_type') -and $settings['server_audit_output_type'] -notmatch '(?i)^file$') { $missing.Add('server_audit_output_type = file') }
    }

    [pscustomobject]@{
        Db          = $Db
        InstallDir  = $installDir
        BinDir      = $binDir
        DataDir     = $dataDir
        PluginDir   = $pluginDir
        ConfigFiles = $configFiles
        FoundFiles  = $found.ToArray()
        Logs        = $logs
        SkipGrant   = Test-OptionOn $settings 'skip_grant_tables'
        Missing     = $missing.ToArray()
    }
}

function New-ReefedLocalBlock($Layout, [string]$FlagsCommand, [int]$FlagsInterval) {
    # Bloco <ossec_config> com os caminhos do banco instalado neste servidor
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add($LocalBegin)
    $lines.Add('<ossec_config>')
    if ($Layout.Db -eq 'postgresql') {
        $lines.Add("  <!-- PostgreSQL: dados em $($Layout.DataDir) -->")
        $lines.Add('  <localfile>')
        $lines.Add('    <log_format>multi-line-regex</log_format>')
        $lines.Add("    <location>$($Layout.LogDir)\$($Layout.LogPattern)</location>")
        $lines.Add('    <multiline_regex match="start" replace="wspace" timeout="3">^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}</multiline_regex>')
        $lines.Add('  </localfile>')
        $lines.Add('  <syscheck>')
        $lines.Add('    <!-- Configuração, autenticação e chaves TLS (regras 110800, 110801 e 110803) -->')
        $lines.Add("    <directories realtime=`"yes`" report_changes=`"yes`" recursion_level=`"0`" restrict=`"postgresql.conf$|postgresql.auto.conf$|pg_hba.conf$|pg_ident.conf$|reefed.conf$|server.key$|server.crt$`">$($Layout.DataDir)</directories>")
        $lines.Add('    <nodiff type="sregex">server.key$</nodiff>')
        $lines.Add('    <!-- Bibliotecas e extensões (regra 110802) -->')
        $lines.Add("    <directories realtime=`"yes`">$($Layout.InstallDir)\lib</directories>")
        $lines.Add("    <directories realtime=`"yes`">$($Layout.InstallDir)\share\extension</directories>")
        $lines.Add('    <!-- Log apagado (regra 110804) -->')
        $lines.Add("    <directories check_all=`"no`" restrict=`".log$`">$($Layout.LogDir)</directories>")
        $lines.Add('  </syscheck>')
    } else {
        $name = 'MySQL'
        if ($Layout.Db -eq 'mariadb') { $name = 'MariaDB' }
        $lines.Add("  <!-- ${name}: dados em $($Layout.DataDir) -->")
        foreach ($kind in $Layout.Logs.Keys) {
            $path = $Layout.Logs[$kind]
            $lines.Add('  <localfile>')
            if ($kind -eq 'slow') {
                $lines.Add('    <log_format>multi-line-regex</log_format>')
                $lines.Add("    <location>$path</location>")
                $lines.Add('    <multiline_regex match="start" replace="wspace" timeout="3">^# Time: </multiline_regex>')
            } else {
                $lines.Add('    <log_format>syslog</log_format>')
                $lines.Add("    <location>$path</location>")
                if ($kind -eq 'general') { $lines.Add("    <restrict type=`"PCRE2`">^\S+\s+\d+ Connect\t</restrict>") }
            }
            $lines.Add('  </localfile>')
        }
        $lines.Add('  <!-- skip-grant-tables na linha de comando ou no my.ini (regra 110056) -->')
        $lines.Add('  <localfile>')
        $lines.Add('    <log_format>full_command</log_format>')
        $lines.Add('    <alias>reefed-db-flags</alias>')
        $lines.Add("    <frequency>$FlagsInterval</frequency>")
        $lines.Add("    <command>$FlagsCommand</command>")
        $lines.Add('  </localfile>')
        $lines.Add('  <syscheck>')
        $lines.Add('    <!-- Configuração (regra 110801) -->')
        $configDirs = @($Layout.FoundFiles | ForEach-Object { Get-ParentPath $_ } | Sort-Object -Unique)
        foreach ($dir in $configDirs) {
            if ($dir -ieq $Layout.DataDir) { continue }
            $lines.Add("    <directories realtime=`"yes`" report_changes=`"yes`" recursion_level=`"0`" restrict=`"my.ini$|my.cnf$`">$dir</directories>")
        }
        $lines.Add('    <!-- Pasta de dados sem tempo real: o agente receberia cada escrita do banco.')
        $lines.Add('         my.ini (MariaDB) e chaves TLS, sem mandar o conteúdo das chaves. -->')
        $lines.Add("    <directories report_changes=`"yes`" recursion_level=`"0`" restrict=`"my.ini$|my.cnf$|.pem$`">$($Layout.DataDir)</directories>")
        $lines.Add('    <nodiff type="sregex">key.pem$</nodiff>')
        $lines.Add('    <!-- Plugins (regra 110802) -->')
        $lines.Add("    <directories realtime=`"yes`">$($Layout.PluginDir)</directories>")
        $lines.Add('    <!-- Log apagado (regra 110804) -->')
        foreach ($path in $Layout.Logs.Values) { $lines.Add("    <directories check_all=`"no`">$path</directories>") }
        $lines.Add('  </syscheck>')
    }
    $lines.Add('</ossec_config>')
    $lines.Add($LocalEnd)
    $lines.ToArray()
}

function Update-OssecConf([string]$Text, [string[]]$Block) {
    # Ajustes do Reefed no ossec.conf do agente (pode rodar de novo: o bloco anterior sai)
    $newline = "`n"
    if ($Text.Contains("`r`n")) { $newline = "`r`n" }

    # FIM: deixa de ignorar *.log (o resto da lista continua)
    $Text = [regex]::Replace($Text, '<ignore type="sregex">([^<]*)</ignore>', {
            param($match)
            $kept = @($match.Groups[1].Value.Split('|') | Where-Object { $_ -ne '.log$' })
            if ($kept.Count -eq 0) { return '' }
            '<ignore type="sregex">' + ($kept -join '|') + '</ignore>'
        })

    $Text = [regex]::Replace($Text, '(?s)\r?\n?' + [regex]::Escape($LocalBegin) + '.*?' + [regex]::Escape($LocalEnd) + '[ \t]*', '')
    $Text = $Text.TrimEnd() + $newline
    if ($Block -and $Block.Count -gt 0) { $Text += $newline + ($Block -join $newline) + $newline }
    $Text
}

function Set-ManagerAddress([string]$Text, [string]$Address) {
    $Text = $Text -replace '<address>[^<]*</address>', "<address>$Address</address>"
    $Text -replace '<manager_address>[^<]*</manager_address>', "<manager_address>$Address</manager_address>"
}

function Set-EnrollmentGroup([string]$Text, [string]$AgentGroups) {
    # Só o <groups> de dentro do <enrollment> (registro automático do agente)
    [regex]::Replace($Text, '(?s)(<enrollment>.*?)<groups>[^<]*</groups>(.*?</enrollment>)', {
            param($match)
            $match.Groups[1].Value + "<groups>$AgentGroups</groups>" + $match.Groups[2].Value
        })
}

function New-DbFlagsScript([string[]]$ConfigFiles) {
    $quoted = @($ConfigFiles | ForEach-Object { "'" + $_.Replace("'", "''") + "'" }) -join ', '
    $script = @'
# Reefed - procura skip-grant-tables no MySQL/MariaDB (regra 110056).
# Gerado pelo install-agent.ps1 do Reefed; o agente roda este arquivo de tempos em tempos.
$pattern = '(?i)(^|\s|--)skip[-_]grant[-_]tables'
$found = $false
try {
    Get-CimInstance -ClassName Win32_Process -Filter "Name = 'mysqld.exe' OR Name = 'mariadbd.exe'" -ErrorAction Stop |
        ForEach-Object { if ($_.CommandLine -match $pattern) { $found = $true } }
} catch { }
foreach ($file in @(__REEFED_CONFIG_FILES__)) {
    if (Test-Path -LiteralPath $file) {
        Get-Content -LiteralPath $file | Where-Object { $_ -notmatch '^\s*[#;]' -and $_ -match $pattern } |
            ForEach-Object { $found = $true }
    }
}
if ($found) { [Console]::Out.Write('REEFED_SKIP_GRANT_TABLES=1') } else { [Console]::Out.Write('REEFED_SKIP_GRANT_TABLES=0') }
'@
    $script.Replace('__REEFED_CONFIG_FILES__', $quoted)
}

# ---------------------------------------------------------------------------
# Passos da instalação

function Read-TextFile([string]$Path) {
    [System.IO.File]::ReadAllText($Path)
}

function Write-TextFile([string]$Path, [string]$Text, [switch]$Bom) {
    # O ossec.conf vai sem BOM; os scripts .ps1 vão com BOM para o Windows PowerShell 5.1
    [System.IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding($Bom.IsPresent)))
}

function Get-AgentDir {
    foreach ($base in @(${env:ProgramFiles(x86)}, $env:ProgramFiles)) {
        if ($base -and (Test-Path -LiteralPath "$base\ossec-agent\wazuh-agent.exe")) { return "$base\ossec-agent" }
    }
    $null
}

function Get-WazuhService {
    $service = Get-Service -Name 'WazuhSvc' -ErrorAction SilentlyContinue
    if (-not $service) { $service = Get-Service -DisplayName 'Wazuh' -ErrorAction SilentlyContinue | Select-Object -First 1 }
    $service
}

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-AgentMsi([string]$Version, [string]$MsiPath, [switch]$SkipSignatureCheck) {
    if ($MsiPath) {
        if (-not (Test-Path -LiteralPath $MsiPath)) { throw "MSI não encontrado: $MsiPath" }
        $msi = (Resolve-Path -LiteralPath $MsiPath).Path
    } else {
        $url = "https://packages.wazuh.com/4.x/windows/wazuh-agent-$Version-1.msi"
        $msi = Join-Path $env:TEMP "wazuh-agent-$Version-1.msi"
        Write-ReefedInfo "baixando $url"
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        $ProgressPreference = 'SilentlyContinue'   # o Windows PowerShell baixa muito mais rápido sem a barra
        Invoke-WebRequest -Uri $url -OutFile $msi -UseBasicParsing
    }
    if (-not $SkipSignatureCheck) {
        $signature = Get-AuthenticodeSignature -FilePath $msi
        $signer = ''
        if ($signature.SignerCertificate) { $signer = $signature.SignerCertificate.Subject }
        if ($signature.Status -ne 'Valid' -or $signer -notmatch 'Wazuh') {
            throw "assinatura do MSI não confere (estado: $($signature.Status), assinante: '$signer'). Baixe de novo; só use -SkipSignatureCheck com um arquivo de origem conhecida."
        }
        Write-ReefedInfo 'assinatura digital do MSI conferida (Wazuh)'
    }
    $msi
}

function Install-Agent([string]$Msi, [string]$Manager, [string]$Password, [string]$Name, [string]$Groups) {
    $log = Join-Path $env:TEMP 'reefed-wazuh-agent-install.log'
    # /liwe: o log do msiexec fica sem a lista de propriedades, onde estaria a senha
    $msiArgs = @('/i', "`"$Msi`"", '/qn', '/norestart', '/liwe', "`"$log`"",
        "WAZUH_MANAGER=`"$Manager`"", "WAZUH_REGISTRATION_SERVER=`"$Manager`"",
        "WAZUH_AGENT_NAME=`"$Name`"", "WAZUH_AGENT_GROUP=`"$Groups`"")
    if ($Password) { $msiArgs += "WAZUH_REGISTRATION_PASSWORD=`"$Password`"" }
    Write-ReefedInfo "instalando o agente do Wazuh (grupos $Groups)"
    $process = Start-Process -FilePath 'msiexec.exe' -ArgumentList $msiArgs -Wait -PassThru
    if ($process.ExitCode -ne 0 -and $process.ExitCode -ne 3010) {
        throw "o msiexec terminou com o código $($process.ExitCode). Veja $log"
    }
}

function Register-Agent([string]$AgentDir, [string]$Manager, [string]$Password, [string]$Name, [string]$Groups) {
    # Agente já instalado: aponta para o servidor do Reefed e registra de novo
    Write-ReefedInfo "agente do Wazuh já instalado; registrando de novo com os grupos $Groups"
    $service = Get-WazuhService
    # Parado, o agente aparece desconectado e o registro novo pode substituir o antigo
    if ($service -and $service.Status -ne 'Stopped') { Stop-Service -InputObject $service -Force }
    $conf = "$AgentDir\ossec.conf"
    $text = Set-EnrollmentGroup (Set-ManagerAddress (Read-TextFile $conf) $Manager) $Groups
    Write-TextFile $conf $text
    $authArgs = @('-m', $Manager, '-A', $Name, '-G', $Groups)
    if ($Password) { $authArgs += @('-P', $Password) }
    & "$AgentDir\agent-auth.exe" @authArgs
    if ($LASTEXITCODE -ne 0) { throw "o registro no servidor do Reefed falhou (agent-auth, código $LASTEXITCODE)" }
}

function Find-DbService([string]$Db, [string]$DbService) {
    $services = @(Get-CimInstance -ClassName Win32_Service)
    if ($DbService) {
        $services = @($services | Where-Object { $_.Name -eq $DbService })
        if ($services.Count -eq 0) { throw "serviço '$DbService' não encontrado" }
    } elseif ($Db -eq 'postgresql') {
        $services = @($services | Where-Object { $_.PathName -match '(?i)\\(pg_ctl|postgres)\.exe' })
    } elseif ($Db -eq 'mariadb') {
        $services = @($services | Where-Object { $_.PathName -match '(?i)\\(mysqld|mariadbd)\.exe' -and $_.PathName -match '(?i)mariadb' })
    } else {
        $services = @($services | Where-Object { $_.PathName -match '(?i)\\mysqld\.exe' -and $_.PathName -notmatch '(?i)mariadb' })
    }
    $running = @($services | Where-Object { $_.State -eq 'Running' })
    if ($running.Count -gt 0) { $services = $running }
    if ($services.Count -gt 1) {
        Write-ReefedWarning "mais de um serviço de $Db ($(@($services | ForEach-Object { $_.Name }) -join ', ')); usando $($services[0].Name). Escolha outro com -DatabaseService."
    }
    $services | Select-Object -First 1
}

function Get-DbLayout([string]$Db, [string]$DbService) {
    $service = Find-DbService $Db $DbService
    if (-not $service) { return $null }
    Write-ReefedInfo "banco encontrado: serviço $($service.Name)"
    $reader = { param($Path) if ($Path -and (Test-Path -LiteralPath $Path)) { Get-Content -LiteralPath $Path } }
    if ($Db -eq 'postgresql') { return Get-PostgresLayout $service.PathName $reader }
    Get-MySqlLayout $Db $service.PathName $reader $env:COMPUTERNAME $env:SystemRoot
}

function Show-DbAdvice($Layout) {
    $db = $Layout.Db
    if ($Layout.Missing.Count -eq 0) {
        Write-ReefedInfo "configuração de log do $db conferida"
        return
    }
    Write-ReefedWarning "falta configurar o log do ${db} para o Reefed:"
    foreach ($item in $Layout.Missing) { Write-ReefedWarning "    $item" }
    if ($db -eq 'postgresql') {
        Write-ReefedWarning "  copie agents\database\postgresql\reefed.conf para $($Layout.DataDir),"
        Write-ReefedWarning "  acrescente no fim do postgresql.conf:  include_if_exists = 'reefed.conf'"
        Write-ReefedWarning "  e recarregue:  & '$($Layout.BinDir)\pg_ctl.exe' reload -D '$($Layout.DataDir)'"
    } else {
        $where = 'my.ini'
        if ($Layout.FoundFiles.Count -gt 0) { $where = $Layout.FoundFiles -join ', ' }
        Write-ReefedWarning "  acrescente essas linhas na seção [mysqld] do $where"
        Write-ReefedWarning "  (modelo em agents\database\$db\, veja docs/agentes.md) e reinicie o serviço do banco"
    }
}

function Enable-FirewallLog {
    Write-ReefedInfo 'ligando o log de conexões bloqueadas do firewall do Windows'
    $commands = @(
        @('advfirewall', 'set', 'allprofiles', 'logging', 'filename', $FirewallLog),
        @('advfirewall', 'set', 'allprofiles', 'logging', 'maxfilesize', '32767'),
        @('advfirewall', 'set', 'allprofiles', 'logging', 'droppedconnections', 'enable')
    )
    foreach ($netshArgs in $commands) {
        & netsh.exe @netshArgs | Out-Null
        if ($LASTEXITCODE -ne 0) { Write-ReefedWarning "netsh $($netshArgs -join ' ') falhou (código $LASTEXITCODE)" }
    }
    try {
        $off = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop |
                Where-Object { "$($_.Enabled)" -eq 'False' } | ForEach-Object { $_.Name })
        if ($off.Count -gt 0) {
            Write-ReefedWarning "firewall do Windows desligado nos perfis $($off -join ', '): o Active Response não consegue bloquear IPs assim."
        }
    } catch {
        Write-ReefedWarning 'não consegui conferir se o firewall do Windows está ligado'
    }
}

function Enable-AuditPolicy {
    Write-ReefedInfo 'ligando a auditoria de logon, contas, grupos e políticas (sucesso e falha)'
    foreach ($guid in $AuditSubcategories.Keys) {
        & auditpol.exe /set "/subcategory:$guid" /success:enable /failure:enable | Out-Null
        if ($LASTEXITCODE -ne 0) { Write-ReefedWarning "auditpol falhou para $($AuditSubcategories[$guid]) (código $LASTEXITCODE)" }
    }
    if ((Get-CimInstance -ClassName Win32_ComputerSystem).PartOfDomain) {
        Write-ReefedWarning 'computador no domínio: uma GPO de auditoria pode desfazer este ajuste. Confira com: auditpol /get /category:*'
    }
}

function Restart-Agent([string]$AgentDir) {
    $service = Get-WazuhService
    if (-not $service) { throw 'serviço do agente do Wazuh não encontrado' }
    Set-Service -InputObject $service -StartupType Automatic
    if ($service.Status -eq 'Running') { Restart-Service -InputObject $service -Force } else { Start-Service -InputObject $service }
    Start-Sleep -Seconds 3
    $service.Refresh()
    if ($service.Status -ne 'Running') { throw "o serviço do agente não ficou rodando; veja $AgentDir\ossec.log" }
}

# ---------------------------------------------------------------------------
# Execução. Carregado com ". .\install-agent.ps1" (testes), só define as funções.
if ($MyInvocation.InvocationName -eq '.') { return }

$ErrorActionPreference = 'Stop'
try {
    if (-not (Test-IsAdmin)) { throw 'abra o PowerShell como administrador' }
    if (-not $Groups) {
        $Groups = 'windows'
        if ($Database) { $Groups = "windows,database,$Database" }
    }

    $agentDir = Get-AgentDir
    if (-not $ConfigureOnly) {
        if (-not $Manager) { throw 'informe -Manager (endereço do servidor do Reefed)' }
        if (-not $Password) { Write-ReefedWarning 'sem -Password: só funciona se o servidor do Reefed não exigir senha de registro' }
        if ($agentDir) {
            Register-Agent $agentDir $Manager $Password $Name $Groups
        } else {
            $msi = Get-AgentMsi $Version $MsiPath -SkipSignatureCheck:$SkipSignatureCheck
            Install-Agent $msi $Manager $Password $Name $Groups
            $agentDir = Get-AgentDir
        }
    }
    if (-not $agentDir) { throw 'agente do Wazuh não encontrado em Program Files\ossec-agent' }

    $block = @()
    if ($Database) {
        $layout = Get-DbLayout $Database $DatabaseService
        if ($layout) {
            $flagsCommand = ''
            if ($Database -ne 'postgresql') {
                New-Item -ItemType Directory -Force -Path "$agentDir\reefed" | Out-Null
                Write-TextFile "$agentDir\reefed\db-flags.ps1" (New-DbFlagsScript $layout.ConfigFiles) -Bom
                $flagsCommand = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$agentDir\reefed\db-flags.ps1`""
                if ($layout.SkipGrant) { Write-ReefedWarning 'skip-grant-tables está ligado no my.ini: o banco aceita login sem senha!' }
            }
            $block = New-ReefedLocalBlock $layout $flagsCommand $FlagsInterval
            Show-DbAdvice $layout
        } else {
            Write-ReefedWarning "não achei o serviço do $Database neste Windows. Os logs do banco não serão lidos;"
            Write-ReefedWarning '  informe o serviço com -DatabaseService NOME (lista: Get-Service) e rode de novo com -ConfigureOnly.'
        }
    }

    $conf = "$agentDir\ossec.conf"
    Copy-Item -LiteralPath $conf -Destination "$conf.reefed-bak" -Force
    Write-TextFile $conf (Update-OssecConf (Read-TextFile $conf) $block)
    Write-ReefedInfo "ajustes do Reefed aplicados em $conf (cópia anterior: $conf.reefed-bak)"

    if (-not $NoFirewall) { Enable-FirewallLog }
    if (-not $NoAuditPolicy) { Enable-AuditPolicy }
    Restart-Agent $agentDir

    if ($ConfigureOnly) { Write-ReefedInfo 'agente reiniciado com os ajustes do Reefed' }
    else { Write-ReefedInfo "agente $Name rodando (grupos $Groups)" }
    Write-ReefedInfo 'confira no servidor do Reefed: make agents   (ou no dashboard, em Agents)'
} catch {
    Write-Host "[reefed] $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
