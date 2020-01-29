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

                # Local group temporarily created for testing.
                LocalGroupName  = 'FSAR_Test'

                CertificateFile = $env:DscPublicCertificatePath
            }
        )
    }
}

configuration MSFT_xFileSystemAccessRule_Prerequisites_Config
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'

    node localhost
    {
        Group 'AddLocalGroup'
        {
            Ensure      = 'Present'
            GroupName   = $Node.LocalGroupName
            Description = 'Group for MSFT_xFileSystemAccessRule tests'
        }
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

configuration MSFT_xFileSystemAccessRule_Cleanup_Config
{
    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'

    node localhost
    {
        Group 'AddLocalGroup'
        {
            Ensure      = 'Absent'
            GroupName   = $Node.LocalGroupName
            Description = 'Group for MSFT_xFileSystemAccessRule tests'
        }
    }
}
