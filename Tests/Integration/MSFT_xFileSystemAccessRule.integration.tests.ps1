$script:dscModuleName = 'xSystemSecurity'
$script:dscResourceName = 'MSFT_xFileSystemAccessRule'

try
{
    Import-Module -Name DscResource.Test -Force -ErrorAction 'Stop'
}
catch [System.IO.FileNotFoundException]
{
    throw 'DscResource.Test module dependency not found. Please run ".\build.ps1 -Tasks build" first.'
}

$script:testEnvironment = Initialize-TestEnvironment `
    -DSCModuleName $script:dscModuleName `
    -DSCResourceName $script:dscResourceName `
    -ResourceType 'Mof' `
    -TestType 'Integration'

try
{
    $ConfigFile = Join-Path -Path $PSScriptRoot -ChildPath "$($script:DSCResourceName).config.ps1"
    . $ConfigFile

    New-Item -Path "$env:SystemDrive\SampleFolder" -ItemType Directory

    Describe "$($script:DSCResourceName)_Integration" {

        It 'New rule - Should compile without throwing' {
            {
                Invoke-Expression -Command "$($script:DSCResourceName)_NewRule -OutputPath `$TestDrive"
            } | Should not throw
        }

        It "New rule - Should apply without throwing" {
            {
                Start-DscConfiguration -Path $TestDrive `
                    -ComputerName localhost -Wait -Verbose -Force
            } | Should not throw
        }

        It 'New rule - Should be able to call Get-DscConfiguration without throwing' {
            { Get-DscConfiguration -Verbose -ErrorAction Stop } | Should Not throw
        }

        It 'New rule - Should have set the resource and all the parameters should match' {
            Test-DscConfiguration -Path $TestDrive | Should Be $true
        }


        It 'Update rule - Should compile without throwing' {
            {
                Invoke-Expression -Command "$($script:DSCResourceName)_UpdateRule -OutputPath `$TestDrive"
            } | Should not throw
        }

        It "Update rule - Should apply without throwing" {
            {
                Start-DscConfiguration -Path $TestDrive `
                    -ComputerName localhost -Wait -Verbose -Force
            } | Should not throw
        }


        It 'Update rule - Should be able to call Get-DscConfiguration without throwing' {
            { Get-DscConfiguration -Verbose -ErrorAction Stop } | Should Not throw
        }

        It 'Remove rule - Should have set the resource and all the parameters should match' {
            Test-DscConfiguration -Path $TestDrive | Should Be $true
        }

        It 'Remove rule - Should compile without throwing' {
            {
                Invoke-Expression -Command "$($script:DSCResourceName)_RemoveRule -OutputPath `$TestDrive"
            } | Should not throw
        }

        It "Remove rule - Should apply without throwing" {
            {
                Start-DscConfiguration -Path $TestDrive `
                    -ComputerName localhost -Wait -Verbose -Force
            } | Should not throw
        }

        It 'Remove rule - Should be able to call Get-DscConfiguration without throwing' {
            { Get-DscConfiguration -Verbose -ErrorAction Stop } | Should Not throw
        }

        It 'New rule - Should have set the resource and all the parameters should match' {
            Test-DscConfiguration -Path $TestDrive | Should Be $true
        }


        Remove-Item -Path "$env:SystemDrive\SampleFolder" -Recurse -Force -Confirm:$false
    }
}
finally
{
    Restore-TestEnvironment -TestEnvironment $TestEnvironment
}
