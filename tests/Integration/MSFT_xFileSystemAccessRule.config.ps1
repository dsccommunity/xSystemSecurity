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

configuration MSFT_xFileSystemAccessRule_NewRule_Config
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

configuration MSFT_xFileSystemAccessRule_UpdateRule_Config
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

configuration MSFT_xFileSystemAccessRule_RemoveRule_Config
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
