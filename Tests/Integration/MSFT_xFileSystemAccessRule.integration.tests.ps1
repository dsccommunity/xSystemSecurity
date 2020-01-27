$script:DSCModuleName = 'xSystemSecurity'
$script:DSCResourceName = 'MSFT_xFileSystemAccessRule'

# Basic integration tests setup
try
{
    $cleanupTestIdentity = $true
    #region SETUP
    $testIdentity = "xFSAR_Test"

    $foundGroup = Get-LocalGroup -Name $testIdentity -ErrorAction SilentlyContinue
    if (-not $foundGroup)
    {
        # create an empty local group if it doesn't already exist,
        # which we will be assigning permissions to a temp folder to in these tests.
        try
        {
            New-LocalGroup -Description "Group for MSFT_xFileSystemAccessRule tests" -Name $testIdentity -ErrorAction 'Stop'
        }
        catch
        {
            if ($_ -like "*Access denied.*")
            {
                # Attempt to use an arbitrary existing group
                $cleanupTestIdentity = $false
                $testIdentity = 'Network Service'
                Write-Warning "Couldn't create a temporary local group. Instead using '$testIdentity'"
            }
            else
            {
                throw "Need to run as administrator"
            }
        }
    }
    #endregion SETUP

    Import-Module "$PSScriptRoot\..\..\DSCResources\MSFT_xFileSystemAccessRule\MSFT_xFileSystemAccessRule.psm1"
    Describe "MSFT_xFileSystemAccessRule Functional unit tests" {
        Context "Test-TargetResource when ACL is absent" {
            BeforeAll {
                $testRoot = "$TestDrive\xFSAR_TestFolder"
                New-Item $testRoot -ItemType Directory -Force -ErrorAction 'Stop'
                Set-TargetResource -Path "$testRoot" -Identity $testIdentity -Rights @() -Ensure Absent

                # Shouldn't throw when run twice, not necessary for DSC but just verifying my test setup is safe
                Set-TargetResource -Path "$testRoot" -Identity $testIdentity -Rights @() -Ensure Absent
            }
            $absentAclTestCases = @(
                @{
                    Rights         = @()
                    Ensure         = 'Absent'
                    ExpectedResult = $true
                    Explanation    = "Permission for nothing absent should succeed as nothing should be present currently"
                },
                @{
                    Rights         = @("Write")
                    Ensure         = 'Present'
                    ExpectedResult = $false
                    Explanation    = "Permissions should have been removed"
                },
                @{
                    Rights         = @("Write", "Read")
                    Ensure         = 'Present'
                    ExpectedResult = $false
                    Explanation    = "Permissions should have been removed"
                },
                @{
                    Rights         = @("Write", "Read")
                    Ensure         = 'Absent'
                    ExpectedResult = $true
                    Explanation    = "Permissions should have been removed"
                },
                @{
                    Rights         = @("Synchronize")
                    Ensure         = 'Absent'
                    ExpectedResult = $true
                    Explanation    = "Permissions should have been removed"
                },
                @{
                    Rights         = @("Read")
                    Ensure         = 'Absent'
                    ExpectedResult = $true
                    Explanation    = "Permissions should have been removed"
                }
            )
            It 'Returns <ExpectedResult> for Ensure <Ensure> and Rights <Rights> with no existing rights' -TestCases $absentAclTestCases {
                Param(
                    $Ensure,
                    $Rights,
                    $ExpectedResult,
                    $Explanation
                )
                $result = Test-TargetResource -Path "$testRoot" -Identity $testIdentity -Rights $Rights -Ensure $Ensure
                $result | Should -Be $ExpectedResult -Because $Explanation
            }
        }


        Context "Set and Test when multiple permissions including a subset is applied" {
            BeforeAll {
                $testRoot = "$TestDrive\xFSAR_TestFolder"
                New-Item $testRoot -ItemType Directory -Force -ErrorAction 'Stop'
                # This should effectively end up as 'Write, ReadAndExecute'
                Set-TargetResource -Path "$testRoot" -Identity $testIdentity -Rights @("Write", "Read", "ExecuteFile") -Ensure Present
            }
            $setSubsetReadAndExecuteTests = @(
                @{
                    Rights         = @("Write")
                    Ensure         = 'Present'
                    ExpectedResult = $true
                    Explanation    = "Permission for write should be added"
                },
                @{
                    Rights         = @("Read")
                    Ensure         = 'Present'
                    ExpectedResult = $true
                    Explanation    = "Permission for read should be added"
                },
                @{
                    Rights         = @("ReadAndExecute")
                    Ensure         = 'Present'
                    ExpectedResult = $true
                    Explanation    = "Permission for ReadAndExecute should be added and supported via Flags"
                },
                @{
                    Rights         = @("FullControl")
                    Ensure         = 'Present'
                    ExpectedResult = $false
                    Explanation    = "Permission for FullControl should NOT exist yet"
                },
                @{
                    Rights         = @("FullControl")
                    Ensure         = 'Absent'
                    ExpectedResult = $true
                    Explanation    = "Permission for FullControl should NOT be considered to be on the object for the absent so test should pass"
                }
            )
            It 'Returns <ExpectedResult> for Ensure <Ensure> and Rights <Rights> with combined multi-rights' -TestCases $setSubsetReadAndExecuteTests {
                Param(
                    $Ensure,
                    $Rights,
                    $ExpectedResult,
                    $Explanation
                )
                $result = Test-TargetResource -Path "$testRoot" -Identity $testIdentity -Rights $Rights -Ensure $Ensure
                $result | Should -Be $ExpectedResult -Because $Explanation
            }
        }

        Context "Set and Test subsets of a big permission like FullControl" {
            BeforeAll {
                $testRoot = "$TestDrive\xFSAR_TestFolder"
                New-Item $testRoot -ItemType Directory -Force -ErrorAction 'Stop'
                Set-TargetResource -Path "$testRoot" -Identity $testIdentity -Rights @("FullControl") -Ensure Present
            }
            $fullControlSubsetTests = @(
                @{
                    Rights         = @("FullControl")
                    Ensure         = 'Present'
                    ExpectedResult = $true
                    Explanation    = "Permission for FullControl should be added now"
                },
                @{
                    Rights         = @("FullControl")
                    Ensure         = 'Absent'
                    ExpectedResult = $false
                    Explanation    = "Permission for FullControl absent should fail"
                },
                @{
                    Rights         = @("Modify")
                    Ensure         = 'Absent'
                    ExpectedResult = $false
                    Explanation    = "Permission for Modify absent should fail as it is encompassed in FullControl"
                },
                @{
                    Rights         = @("Modify")
                    Ensure         = 'Present'
                    ExpectedResult = $true
                    Explanation    = "Permission for Modify true should succeed as it is encompassed in FullControl"
                },
                @{
                    Rights         = @("Read")
                    Ensure         = 'Absent'
                    ExpectedResult = $false
                    Explanation    = "Permission for Read absent should fail as it is encompassed in FullControl"
                },
                @{
                    Rights         = @("Read", "Write")
                    Ensure         = 'Absent'
                    ExpectedResult = $false
                    Explanation    = "Permission for Read and Write absent should fail as both is encompassed in FullControl"
                },
                @{
                    Rights         = @("Read", "Write")
                    Ensure         = 'Present'
                    ExpectedResult = $true
                    Explanation    = "Permission for Read and Write present should succeed as both are encompassed in FullControl"
                },
                @{
                    Rights         = @("Read", "Write", "ExecuteFile")
                    Ensure         = 'Present'
                    ExpectedResult = $true
                    Explanation    = "Permission for Read and Write absent should fail as both is encompassed in FullControl"
                }
            )
            It 'Returns <ExpectedResult> for Ensure <Ensure> and Rights <Rights> with FullControl existing rights' -TestCases $fullControlSubsetTests {
                Param(
                    $Ensure,
                    $Rights,
                    $ExpectedResult,
                    $Explanation
                )
                $result = Test-TargetResource -Path "$testRoot" -Identity $testIdentity -Rights $Rights -Ensure $Ensure
                $result | Should -Be $ExpectedResult -Because $Explanation
            }
        }

        Context "Set and Test against an existing multi-flag permission: Read, Write" {
            BeforeAll {
                $testRoot = "$TestDrive\xFSAR_TestFolder"
                New-Item $testRoot -ItemType Directory -Force -ErrorAction 'Stop'
                Set-TargetResource -Path "$testRoot" -Identity $testIdentity -Rights @() -Ensure Absent

                Set-TargetResource -Path "$testRoot" -Identity $testIdentity -Rights @("Read", "Write") -Ensure Present
            }

            $existingMultiPermission = @(
                @{
                    Rights         = @()
                    Ensure         = 'Absent'
                    ExpectedResult = $false
                    Explanation    = "Permission for nothing absent should fail as there are permissions to remove currently"
                },
                @{
                    Rights         = @("Read", "Write")
                    Ensure         = 'Absent'
                    ExpectedResult = $false
                    Explanation    = "Permission for Read and Write absent should fail as both are present"
                },
                @{
                    Rights         = @("Read", "FullControl")
                    Ensure         = 'Absent'
                    ExpectedResult = $false
                    Explanation    = "Permission for Read and FullControl absent should fail as Read is present currently even though FullControl is not"
                },
                @{
                    Rights         = @('Read')
                    Ensure         = 'Absent'
                    ExpectedResult = $false
                    Explanation    = "Permission for Read absent should fail as Read is present currently"
                },
                @{
                    Rights         = @('Read')
                    Ensure         = 'Present'
                    ExpectedResult = $true
                    Explanation    = "Permission Read is present currently"
                },
                @{
                    Rights         = @('Write')
                    Ensure         = 'Present'
                    ExpectedResult = $true
                    Explanation    = "Permission Write is present currently"
                },
                @{
                    Rights         = @('Read', 'Write')
                    Ensure         = 'Present'
                    ExpectedResult = $true
                    Explanation    = "Permission Read and Write are present currently"
                },
                @{
                    Rights         = @('Synchronize')
                    Ensure         = 'Present'
                    ExpectedResult = $true
                    Explanation    = "Permission Read should have applied Synchronize automatically by the operating system"
                }
            )
            It 'Returns <ExpectedResult> for Ensure <Ensure> and Rights <Rights> with Read, Write existing rights' -TestCases $existingMultiPermission {
                Param(
                    $Ensure,
                    $Rights,
                    $ExpectedResult,
                    $Explanation
                )
                $result = Test-TargetResource -Path "$testRoot" -Identity $testIdentity -Rights $Rights -Ensure $Ensure
                $result | Should -Be $ExpectedResult -Because $Explanation
            }
        }

        Context "Set and Test against a non-existant user" {
            BeforeAll {
                $testRoot = "$TestDrive\xFSAR_TestFolder"
                New-Item $testRoot -ItemType Directory -Force -ErrorAction 'Stop'
                Set-TargetResource -Path "$testRoot" -Identity $testIdentity -Rights @() -Ensure Absent

                Set-TargetResource -Path "$testRoot" -Identity $testIdentity -Rights @("Read", "Write") -Ensure Present
            }

            $nonExistantUserPermission = @(
                @{
                    Rights         = @()
                    Ensure         = 'Absent'
                    ExpectedResult = $true
                    Explanation    = "Permission for unspecified absent on something with no ACLs should succeed"
                    Identity       = "Fake"
                },
                @{
                    Rights         = @("Write")
                    Ensure         = 'Absent'
                    ExpectedResult = $true
                    Explanation    = "Permission for Write absent on something with no ACLs should succeed"
                    Identity       = "Fake"
                },
                @{
                    Rights         = @("Read")
                    Ensure         = 'Present'
                    ExpectedResult = $false
                    Explanation    = "Permission for Read present on something that doesn't exist should not pass"
                    Identity       = "Fake"
                }
            )
            It 'Returns <ExpectedResult> for Ensure <Ensure> and Rights <Rights> for a non-existent identity' -TestCases $nonExistantUserPermission {
                Param(
                    $Ensure,
                    $Rights,
                    $ExpectedResult,
                    $Explanation,
                    $Identity
                )
                $result = Test-TargetResource -Path "$testRoot" -Identity $Identity -Rights $Rights -Ensure $Ensure
                $result | Should -Be $ExpectedResult -Because $Explanation
            }
        }
    }
}
finally
{
    if ($cleanupTestIdentity)
    {
        Get-LocalGroup $testIdentity -ErrorAction 'SilentlyContinue' | Remove-LocalGroup -ErrorAction 'Stop'
    }
}


[String] $script:moduleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if ( (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests'))) -or `
    (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1'))) )
{
    & git @('clone', 'https://github.com/PowerShell/DscResource.Tests.git', (Join-Path -Path $script:moduleRoot -ChildPath '\DSCResource.Tests\'))
}

Import-Module (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1') -Force
$initializeTestEnvironmentSplat = @{
    DscResourceName = $script:DSCResourceName
    TestType = 'Integration'
    DscModuleName = $script:DSCModuleName
}
$TestEnvironment = Initialize-TestEnvironment @initializeTestEnvironmentSplat

New-Item -Path "$env:SystemDrive\SampleFolder" -ItemType Directory
try
{
    $ConfigFile = Join-Path -Path $PSScriptRoot -ChildPath "$($script:DSCResourceName).config.ps1"
    . $ConfigFile

    Describe "$($script:DSCResourceName)_Integration" {

        It 'New rule - Should compile without throwing' {
            Invoke-Expression -Command "$($script:DSCResourceName)_NewRule -OutputPath `$TestDrive"
        }

        It "New rule - Should apply without throwing" {
            Start-DscConfiguration -Path $TestDrive -ComputerName localhost -Wait -Verbose -Force -ErrorAction 'Stop'
        }

        It 'New rule - Should be able to call Get-DscConfiguration without throwing' {
            Get-DscConfiguration -Verbose -ErrorAction Stop
        }

        It 'New rule - Should have set the resource and all the parameters should match' {
            Test-DscConfiguration -Path $TestDrive -ErrorAction 'Stop' | Should Be $true
        }


        It 'Update rule - Should compile without throwing' {
            Invoke-Expression -Command "$($script:DSCResourceName)_UpdateRule -OutputPath `$TestDrive" -ErrorAction 'Stop'
        }

        It "Update rule - Should apply without throwing" {
            Start-DscConfiguration -Path $TestDrive -ComputerName localhost -Wait -Verbose -Force -ErrorAction 'Stop'
        }


        It 'Update rule - Should be able to call Get-DscConfiguration without throwing' {
            Get-DscConfiguration -Verbose -ErrorAction Stop
        }

        It 'Remove rule - Should have set the resource and all the parameters should match' {
            Test-DscConfiguration -Path $TestDrive -ErrorAction 'Stop' | Should Be $true
        }

        It 'Remove rule - Should compile without throwing' {
            Invoke-Expression -Command "$($script:DSCResourceName)_RemoveRule -OutputPath `$TestDrive" -ErrorAction 'Stop'
        }

        It "Remove rule - Should apply without throwing" {
            Start-DscConfiguration -Path $TestDrive -ComputerName localhost -Wait -Verbose -Force -ErrorAction 'Stop'
        }

        It 'Remove rule - Should be able to call Get-DscConfiguration without throwing' {
            Get-DscConfiguration -Verbose -ErrorAction Stop
        }

        It 'New rule - Should have set the resource and all the parameters should match' {
            Test-DscConfiguration -Path $TestDrive -ErrorAction 'Stop' | Should Be $true
        }
    }
}
finally
{
    Remove-Item -Path "$env:SystemDrive\SampleFolder" -Recurse -Force -Confirm:$false -ErrorAction 'SilentlyContinue'
    Restore-TestEnvironment -TestEnvironment $TestEnvironment
}
