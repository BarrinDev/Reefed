# Análise estática do agents/windows/install-agent.ps1 (roda no CI).
# O script precisa funcionar no Windows PowerShell 5.1, que vem com o Windows
# Server 2016+ e o Windows 10/11: as regras de compatibilidade conferem isso.
@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        # Instalador interativo: as mensagens são para quem está na tela
        'PSAvoidUsingWriteHost',
        # Funções internas do script, chamadas uma vez cada; não fazem sentido com -WhatIf
        'PSUseShouldProcessForStateChangingFunctions'
    )
    Rules        = @{
        PSUseCompatibleSyntax   = @{
            Enable         = $true
            TargetVersions = @('5.1', '7.0')
        }
        PSUseCompatibleCommands = @{
            Enable         = $true
            TargetProfiles = @(
                'win-8_x64_10.0.17763.0_5.1.17763.316_x64_4.0.30319.42000_framework',
                'win-48_x64_10.0.17763.0_5.1.17763.316_x64_4.0.30319.42000_framework'
            )
        }
        PSUseCompatibleTypes    = @{
            Enable         = $true
            TargetProfiles = @(
                'win-8_x64_10.0.17763.0_5.1.17763.316_x64_4.0.30319.42000_framework'
            )
        }
    }
}
