#region HEADER
# Integration Test Config Template Version: 1.2.0
#endregion

$configFile = [System.IO.Path]::ChangeExtension($MyInvocation.MyCommand.Path, 'json')
if (Test-Path -Path $configFile)
{
    <#
        Allows reading the configuration data from a JSON file,
        for real testing scenarios outside of the CI.
    #>
    $ConfigurationData = Get-Content -Path $configFile | ConvertFrom-Json
}
else
{
    $ConfigurationData = @{
        AllNodes = @(
            @{
                NodeName        = 'localhost'

                <#
                    Path is set to a correct value in the configuration prior to
                    running each configuration.
                #>
                Path            = ''

                CertificateFile = $env:DscPublicCertificatePath
            }
        )
    }
}

configuration MSFT_xFileSystemAccessRule_NewRule
{
    Import-DscResource -ModuleName 'xSystemSecurity'

    node localhost
    {
        xFileSystemAccessRule Integration_Test
        {
            Path     = $Node.Path
            Identity = 'NT AUTHORITY\NETWORK SERVICE'
            Rights   = @('Read', 'Synchronize')
        }
    }
}

configuration MSFT_xFileSystemAccessRule_UpdateRule
{
    Import-DscResource -ModuleName 'xSystemSecurity'

    node localhost
    {
        xFileSystemAccessRule Integration_Test
        {
            Path     = $Node.Path
            Identity = 'NT AUTHORITY\NETWORK SERVICE'
            Rights   = @('FullControl')
        }
    }
}

configuration MSFT_xFileSystemAccessRule_RemoveRule
{
    Import-DscResource -ModuleName 'xSystemSecurity'

    node localhost
    {
        xFileSystemAccessRule Integration_Test
        {
            Path     = $Node.Path
            Identity = 'NT AUTHORITY\NETWORK SERVICE'
            Ensure   = 'Absent'
        }
    }
}

<#
    .SYNOPSIS
        Configures database mail.

    .NOTES
        This also enables the option 'Database Mail XPs'.
#>
Configuration MSFT_xFileSystemAccessRule_Add_Config
{
    Import-DscResource -ModuleName 'xSystemSecurity'

    node $AllNodes.NodeName
    {
        SqlServerConfiguration 'EnableDatabaseMailXPs'
        {
            ServerName     = $Node.ServerName
            InstanceName   = $Node.InstanceName
            OptionName     = 'Database Mail XPs'
            OptionValue    = 1
            RestartService = $false
        }

        SqlServerDatabaseMail 'Integration_Test'
        {
            Ensure               = 'Present'
            ServerName           = $Node.ServerName
            InstanceName         = $Node.InstanceName
            AccountName          = $Node.AccountName
            ProfileName          = $Node.ProfileName
            EmailAddress         = $Node.EmailAddress
            ReplyToAddress       = $Node.EmailAddress
            DisplayName          = $Node.MailServerName
            MailServerName       = $Node.MailServerName
            Description          = $Node.Description
            LoggingLevel         = $Node.LoggingLevel
            TcpPort              = $Node.TcpPort

            PsDscRunAsCredential = New-Object `
                -TypeName System.Management.Automation.PSCredential `
                -ArgumentList @($Node.Username, (ConvertTo-SecureString -String $Node.Password -AsPlainText -Force))
        }
    }
}
