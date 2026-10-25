<#
    Testes das funções do agents/windows/install-agent.ps1 que não mexem no sistema:
    leitura da linha de comando dos serviços, do postgresql.conf e do my.ini, bloco
    gerado para o ossec.conf e verificação de skip-grant-tables.

    Rodam no Windows PowerShell 5.1 e no PowerShell 7 (inclusive no Linux, no CI):
        pwsh -NoProfile -File tests/windows/test-install-agent.ps1
#>
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $root 'agents/windows/install-agent.ps1')

$script:failures = 0
$script:checks = 0
function Assert-That([bool]$Condition, [string]$What) {
    $script:checks++
    if (-not $Condition) {
        $script:failures++
        Write-Host "FALHOU: $What" -ForegroundColor Red
    }
}
function Assert-Equal($Actual, $Expected, [string]$What) {
    Assert-That ("$Actual" -ceq "$Expected") "$What`n    esperado: $Expected`n    obtido:   $Actual"
}
function New-Reader([hashtable]$Files) {
    # Simula Get-Content: devolve as linhas do "arquivo" ou nada
    { param($Path) if ($Files.ContainsKey($Path)) { $Files[$Path] -split "`r?`n" } }.GetNewClosure()
}
function Read-RepoFile([string]$Relative) {
    Get-Content -LiteralPath (Join-Path $root $Relative)
}

# --------------------------------------------------------------------- parâmetros do script
# Get-Command monta os parâmetros como o PowerShell faz ao rodar o script
# (um parâmetro -Db, por exemplo, colide com o apelido -db do -Debug)
$command = Get-Command (Join-Path $root 'agents/windows/install-agent.ps1')
foreach ($name in @('Manager', 'Password', 'Name', 'Groups', 'Database', 'DatabaseService', 'Version', 'MsiPath', 'ConfigureOnly')) {
    Assert-That $command.Parameters.ContainsKey($name) "parâmetro -$name"
}

# --------------------------------------------------------------------- linha de comando
$pgService = '"C:\Program Files\PostgreSQL\17\bin\pg_ctl.exe" runservice -N "postgresql-x64-17" -D "C:\Program Files\PostgreSQL\17\data" -w'
$tokens = @(Split-CommandLine $pgService)
Assert-Equal $tokens.Count 7 'PostgreSQL: número de partes da linha de comando'
Assert-Equal $tokens[0] 'C:\Program Files\PostgreSQL\17\bin\pg_ctl.exe' 'PostgreSQL: executável'
Assert-Equal $tokens[5] 'C:\Program Files\PostgreSQL\17\data' 'PostgreSQL: pasta de dados com espaço'

$mysqlService = '"C:\Program Files\MySQL\MySQL Server 8.4\bin\mysqld.exe" --defaults-file="C:\ProgramData\MySQL\MySQL Server 8.4\my.ini" MySQL84'
$tokens = @(Split-CommandLine $mysqlService)
Assert-Equal $tokens[1] '--defaults-file=C:\ProgramData\MySQL\MySQL Server 8.4\my.ini' 'MySQL: aspas só no valor'

$mariaService = '"C:\Program Files\MariaDB 11.4\bin\mysqld.exe" "--defaults-file=C:\Program Files\MariaDB 11.4\data\my.ini" "MariaDB"'
$tokens = @(Split-CommandLine $mariaService)
Assert-Equal $tokens[1] '--defaults-file=C:\Program Files\MariaDB 11.4\data\my.ini' 'MariaDB: aspas no argumento inteiro'
Assert-Equal $tokens[2] 'MariaDB' 'MariaDB: nome do serviço'

Assert-Equal (Resolve-DbPath 'C:/ProgramData/MySQL/MySQL Server 8.4/Data' 'X:\') 'C:\ProgramData\MySQL\MySQL Server 8.4\Data' 'caminho com / vira \'
Assert-Equal (Resolve-DbPath '"HOST.err"' 'C:\dados') 'C:\dados\HOST.err' 'caminho relativo entre aspas'
Assert-Equal (Resolve-DbPath '.\log' 'C:\pg\data\') 'C:\pg\data\log' 'caminho relativo com .\'
Assert-Equal (Resolve-DbPath 'C:\\logs\\mysql' 'X:\') 'C:\logs\mysql' 'barras dobradas do my.ini'

# --------------------------------------------------------------------- PostgreSQL
$pgConf = @"
# postgresql.conf gerado pelo instalador da EDB
listen_addresses = '*'		# what IP address(es) to listen on;
port = 5432				# (change requires restart)
logging_collector = on		# Enable capturing of stderr
log_directory = 'log'			# directory where log files are written,
log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'	# log file name pattern,
#log_line_prefix = '%m [%p] '		# special values:
log_timezone = 'America/Sao_Paulo'
"@
$data = 'C:\Program Files\PostgreSQL\17\data'
$files = @{ "$data\postgresql.conf" = $pgConf }
$layout = Get-PostgresLayout $pgService (New-Reader $files)
Assert-Equal $layout.DataDir $data 'PostgreSQL: pasta de dados'
Assert-Equal $layout.BinDir 'C:\Program Files\PostgreSQL\17\bin' 'PostgreSQL: pasta bin'
Assert-Equal $layout.InstallDir 'C:\Program Files\PostgreSQL\17' 'PostgreSQL: pasta de instalação'
Assert-Equal $layout.LogDir "$data\log" 'PostgreSQL: pasta de log relativa'
Assert-Equal $layout.LogPattern 'postgresql-*.log' 'PostgreSQL: curinga do nome do log'
Assert-That ($layout.Missing -contains "log_line_prefix = '$PgLinePrefix'") 'PostgreSQL sem o reefed.conf: falta o log_line_prefix'
Assert-That ($layout.Missing -contains 'log_connections = on') 'PostgreSQL sem o reefed.conf: falta log_connections'
Assert-That ($layout.Missing -notcontains 'logging_collector = on') 'PostgreSQL: logging_collector ligado pelo instalador'

# Com o reefed.conf do repositório incluído no fim, não falta nada
$files["$data\postgresql.conf"] = $pgConf + "`ninclude_if_exists = 'reefed.conf'`n"
$files["$data\reefed.conf"] = (Read-RepoFile 'agents/database/postgresql/reefed.conf') -join "`n"
$layout = Get-PostgresLayout $pgService (New-Reader $files)
Assert-Equal ($layout.Missing -join '; ') '' 'PostgreSQL com o reefed.conf do repositório: configuração completa'

# ALTER SYSTEM (postgresql.auto.conf) vale por último
$files["$data\postgresql.auto.conf"] = "log_statement = 'none'`nlog_directory = 'D:/pglogs'"
$layout = Get-PostgresLayout $pgService (New-Reader $files)
Assert-That ($layout.Missing -contains "log_statement = 'all'") 'PostgreSQL: postgresql.auto.conf desliga o log de comandos'
Assert-Equal $layout.LogDir 'D:\pglogs' 'PostgreSQL: log_directory absoluto no postgresql.auto.conf'

# --------------------------------------------------------------------- MySQL
$myIniInstaller = @"
[client]
port=3306
[mysql]
no-beep
[mysqld]
port=3306
datadir=C:/ProgramData/MySQL/MySQL Server 8.4/Data
default-storage-engine=INNODB
sql-mode="ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION"
log-output=FILE
general-log=0
general_log_file="DBSRV01.log"
slow-query-log=1
slow_query_log_file="DBSRV01-slow.log"
long_query_time=10
log-error="DBSRV01.err"
log-bin="DBSRV01-bin"
server-id=1
secure-file-priv="C:/ProgramData/MySQL/MySQL Server 8.4/Uploads"
"@
$myIni = 'C:\ProgramData\MySQL\MySQL Server 8.4\my.ini'
$myData = 'C:\ProgramData\MySQL\MySQL Server 8.4\Data'
$layout = Get-MySqlLayout 'mysql' $mysqlService (New-Reader @{ $myIni = $myIniInstaller }) 'DBSRV01' 'C:\Windows'
Assert-Equal $layout.DataDir $myData 'MySQL: pasta de dados do my.ini'
Assert-Equal $layout.Logs['error'] "$myData\DBSRV01.err" 'MySQL: log de erros relativo à pasta de dados'
Assert-Equal $layout.Logs['slow'] "$myData\DBSRV01-slow.log" 'MySQL: slow log'
Assert-Equal $layout.Logs['general'] "$myData\DBSRV01.log" 'MySQL: general log'
Assert-Equal $layout.PluginDir 'C:\Program Files\MySQL\MySQL Server 8.4\lib\plugin' 'MySQL: pasta de plugins'
Assert-Equal ($layout.FoundFiles -join ',') $myIni 'MySQL: só o --defaults-file vale'
Assert-Equal ($layout.Missing -join '; ') 'log_error_verbosity = 3; long_query_time = 0; log_slow_extra = ON; log_slow_admin_statements = ON; general_log = ON' 'MySQL: o que falta no my.ini do instalador'
Assert-That (-not $layout.SkipGrant) 'MySQL: sem skip-grant-tables'

# my.ini com a configuração do Reefed para Windows (docs/agentes.md)
$reefedIni = $myIniInstaller -replace 'general-log=0', 'general-log=1' -replace 'long_query_time=10', 'long_query_time=0'
$reefedIni += "`nlog_error_verbosity = 3`nlog_slow_extra = ON`nlog_slow_admin_statements = ON  # comandos administrativos também`n"
$layout = Get-MySqlLayout 'mysql' $mysqlService (New-Reader @{ $myIni = $reefedIni }) 'DBSRV01' 'C:\Windows'
Assert-Equal ($layout.Missing -join '; ') '' 'MySQL com a configuração do Reefed: nada falta'

# skip-grant-tables no my.ini
$layout = Get-MySqlLayout 'mysql' $mysqlService (New-Reader @{ $myIni = $reefedIni + "skip-grant-tables`n" }) 'DBSRV01' 'C:\Windows'
Assert-That $layout.SkipGrant 'MySQL: skip-grant-tables no my.ini'

# Serviço sem --defaults-file: lista padrão de arquivos do Windows; nomes padrão dos logs
$plain = '"D:\mysql\bin\mysqld.exe" MySQL'
$layout = Get-MySqlLayout 'mysql' $plain (New-Reader @{ 'C:\Windows\my.ini' = "[mysqld]`ndatadir=D:/mysql/data`n" }) 'DBSRV01' 'C:\Windows'
Assert-Equal ($layout.FoundFiles -join ',') 'C:\Windows\my.ini' 'MySQL sem --defaults-file: acha o C:\Windows\my.ini'
Assert-Equal $layout.ConfigFiles.Count 6 'MySQL sem --defaults-file: confere os 6 arquivos padrão'
Assert-Equal $layout.Logs['error'] 'D:\mysql\data\DBSRV01.err' 'MySQL: nome padrão do log de erros'
Assert-Equal $layout.Logs['slow'] 'D:\mysql\data\DBSRV01-slow.log' 'MySQL: nome padrão do slow log'

# --------------------------------------------------------------------- MariaDB
$mariaIni = @"
[mysqld]
datadir=C:/Program Files/MariaDB 11.4/data
port=3306
innodb_buffer_pool_size=511M
character-set-server=utf8mb4
[client]
port=3306
plugin-dir=C:\Program Files\MariaDB 11.4/lib/plugin
"@
$mariaPath = 'C:\Program Files\MariaDB 11.4\data\my.ini'
$layout = Get-MySqlLayout 'mariadb' $mariaService (New-Reader @{ $mariaPath = $mariaIni }) 'DBSRV01' 'C:\Windows'
Assert-Equal $layout.Logs['audit'] 'C:\Program Files\MariaDB 11.4\data\server_audit.log' 'MariaDB: log de auditoria padrão'
Assert-That ($layout.Missing -contains 'plugin_load_add = server_audit') 'MariaDB sem auditoria: falta o plugin'

# Com o reefed.cnf do repositório (caminho do log trocado como manda o comentário dele)
$cnf = (Read-RepoFile 'agents/database/mariadb/reefed.cnf') -join "`n"
$cnf = $cnf -replace '(?m)^server_audit_file_path\s*=.*$', 'server_audit_file_path        = server_audit.log'
$layout = Get-MySqlLayout 'mariadb' $mariaService (New-Reader @{ $mariaPath = $mariaIni + "`n" + $cnf }) 'DBSRV01' 'C:\Windows'
Assert-Equal ($layout.Missing -join '; ') '' 'MariaDB com o reefed.cnf do repositório: nada falta'
Assert-Equal $layout.Logs['audit'] 'C:\Program Files\MariaDB 11.4\data\server_audit.log' 'MariaDB: log relativo à pasta de dados'

# --------------------------------------------------------------------- ossec.conf
$winConf = (@(
        '<!--'
        '  Wazuh - Agent - Default configuration for Windows'
        '-->'
        ''
        '<ossec_config>'
        '  <client>'
        '    <server>'
        '      <address>0.0.0.0</address>'
        '      <port>1514</port>'
        '      <protocol>tcp</protocol>'
        '    </server>'
        '    <enrollment>'
        '      <enabled>yes</enabled>'
        '      <manager_address>0.0.0.0</manager_address>'
        '      <groups>default</groups>'
        '    </enrollment>'
        '  </client>'
        '  <syscheck>'
        '    <ignore type="sregex">.log$|.htm$|.jpg$|.png$|.chm$|.pnf$|.evtx$</ignore>'
        '  </syscheck>'
        '</ossec_config>'
    ) -join "`r`n") + "`r`n"

$files.Remove("$data\postgresql.auto.conf")
$pgLayout = Get-PostgresLayout $pgService (New-Reader $files)
$block = New-ReefedLocalBlock $pgLayout '' 300
$once = Update-OssecConf $winConf $block
$twice = Update-OssecConf $once $block
Assert-That ($once -ceq $twice) 'ossec.conf: rodar duas vezes dá o mesmo resultado'
Assert-That ($once.Contains('<ignore type="sregex">.htm$|.jpg$|.png$|.chm$|.pnf$|.evtx$</ignore>')) 'ossec.conf: .log$ sai da lista de ignorados do FIM'
Assert-That ($once.Contains("<location>$data\log\postgresql-*.log</location>")) 'ossec.conf: log do PostgreSQL'
Assert-That (-not ($once -match '[^\r]\n')) 'ossec.conf: mantém o fim de linha do Windows'
Assert-Equal ([regex]::Matches($once, 'REEFED-LOCAL-BEGIN').Count) 1 'ossec.conf: um bloco do Reefed só'
[xml]$parsed = "<raiz>$($once -replace '<\?xml[^>]*\?>', '')</raiz>"
Assert-Equal @($parsed.raiz.ossec_config).Count 2 'ossec.conf: XML válido com o bloco do Reefed'

$cleared = Update-OssecConf $once @()
Assert-That (-not $cleared.Contains('REEFED-LOCAL')) 'ossec.conf: sem banco, o bloco anterior sai'

$updated = Set-EnrollmentGroup (Set-ManagerAddress $winConf '10.0.0.10') 'windows,database,mysql'
Assert-That ($updated.Contains('<address>10.0.0.10</address>') -and $updated.Contains('<manager_address>10.0.0.10</manager_address>')) 'ossec.conf: endereço do servidor do Reefed'
Assert-That ($updated.Contains('<groups>windows,database,mysql</groups>')) 'ossec.conf: grupos do registro automático'

$myLayout = Get-MySqlLayout 'mysql' $mysqlService (New-Reader @{ $myIni = $reefedIni }) 'DBSRV01' 'C:\Windows'
$command = 'powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "C:\Program Files (x86)\ossec-agent\reefed\db-flags.ps1"'
$myBlock = New-ReefedLocalBlock $myLayout $command 300
[xml]$parsed = "<raiz>$($myBlock -join "`n")</raiz>"
$localfiles = @($parsed.raiz.ossec_config.localfile)
Assert-Equal $localfiles.Count 4 'MySQL: três logs e a verificação de skip-grant-tables'
Assert-Equal ($localfiles | Where-Object { $_.alias -eq 'reefed-db-flags' }).command $command 'MySQL: comando da verificação'
$dirs = @($parsed.raiz.ossec_config.syscheck.directories | ForEach-Object { $_.'#text' })
Assert-That ($dirs -contains 'C:\ProgramData\MySQL\MySQL Server 8.4') 'MySQL: FIM na pasta do my.ini'
Assert-That ($dirs -contains "$myData\DBSRV01.err") 'MySQL: FIM no log de erros (apagado)'
Assert-Equal (@($dirs | Group-Object | Where-Object { $_.Count -gt 1 }).Count) 0 'MySQL: nenhuma pasta repetida no FIM'
Assert-That (-not ($myBlock -join "`n").Contains('&')) 'bloco sem "&" (o Wazuh não decodifica entidades XML)'

$mariaLayout = Get-MySqlLayout 'mariadb' $mariaService (New-Reader @{ $mariaPath = $mariaIni + "`n" + $cnf }) 'DBSRV01' 'C:\Windows'
[xml]$parsed = "<raiz>$((New-ReefedLocalBlock $mariaLayout $command 300) -join "`n")</raiz>"
$dirs = @($parsed.raiz.ossec_config.syscheck.directories | ForEach-Object { $_.'#text' })
Assert-Equal (@($dirs | Where-Object { $_ -eq 'C:\Program Files\MariaDB 11.4\data' }).Count) 1 'MariaDB: my.ini na pasta de dados aparece uma vez só no FIM'

# --------------------------------------------------------------------- skip-grant-tables
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("reefed-test-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    $ini = Join-Path $tmp "my 'teste'.ini"
    $flags = Join-Path $tmp 'db-flags.ps1'
    Write-TextFile $flags (New-DbFlagsScript @($ini, (Join-Path $tmp 'nao-existe.ini'))) -Bom
    $errors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile($flags, [ref]$null, [ref]$errors)
    Assert-Equal $errors.Count 0 'db-flags.ps1 gerado sem erro de sintaxe'

    $shell = (Get-Process -Id $PID).Path
    foreach ($case in @(
            @{ Content = "[mysqld]`nport=3306`n"; Expected = 'REEFED_SKIP_GRANT_TABLES=0'; What = 'sem a opção' },
            @{ Content = "[mysqld]`n# skip-grant-tables`n"; Expected = 'REEFED_SKIP_GRANT_TABLES=0'; What = 'opção comentada' },
            @{ Content = "[mysqld]`nskip_grant_tables`n"; Expected = 'REEFED_SKIP_GRANT_TABLES=1'; What = 'opção ligada' }
        )) {
        Set-Content -LiteralPath $ini -Value $case.Content
        $output = & $shell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $flags
        Assert-Equal "$output" $case.Expected "db-flags.ps1: $($case.What)"
    }
} finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force
}

# ---------------------------------------------------------------------
if ($script:failures -gt 0) {
    Write-Host "$script:failures de $script:checks verificações falharam" -ForegroundColor Red
    exit 1
}
Write-Host "install-agent.ps1: $script:checks verificações ok" -ForegroundColor Green
