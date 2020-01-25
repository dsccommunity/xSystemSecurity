#region HEADER

# Unit Test Template Version: 1.2.1
$script:moduleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if ( (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests'))) -or `
     (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1'))) )
{
    & git @('clone','https://github.com/PowerShell/DscResource.Tests.git',(Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests'))
}

Import-Module -Name (Join-Path -Path $script:moduleRoot -ChildPath (Join-Path -Path 'DSCResource.Tests' -ChildPath 'TestHelper.psm1')) -Force

$TestEnvironment = Initialize-TestEnvironment `
    -DSCModuleName 'xSystemSecurity' `
    -DSCResourceName 'MSFT_xFileSystemAccessRule' `
    -TestType Unit

#endregion HEADER

function Invoke-TestSetup {}

function Invoke-TestCleanup
{
    Restore-TestEnvironment -TestEnvironment $TestEnvironment
}

# Begin Testing
try
{
    Invoke-TestSetup

    InModuleScope 'MSFT_xFileSystemAccessRule' {

        #region Mock Variables
        $mockClusterName = 'Cluster1'
        $mockClusterNodes = @(
            $env:COMPUTERNAME,
            'Node1',
            'Node2'
        )
        $mockIdentity = 'NT AUTHORITY\NETWORK SERVICE'
        $mockPath = "$($env:SystemDrive)\TestFolder"
        $mockRights = @('ReadData','WriteAttributes')
        # The filesystem doesn't return a string array for ACLs, it returns a bit-flagged [System.Security.AccessControl.FileSystemRights]
        $mockRightsResult = [System.Security.AccessControl.FileSystemRights] @('ReadData','WriteAttributes')
        $mockTestPathResult = $true
        #endregion Mock Variables

        #region Cmdlet Mocks
        $mockGetAcl = {
            return New-Object -TypeName PsObject |
            Add-Member -MemberType NoteProperty -Name Access -Value @(
                New-Object -TypeName PsObject |
                    Add-Member -MemberType NoteProperty -Name IdentityReference -Value $mockIdentity -PassThru |
                    Add-Member -MemberType NoteProperty -Name FileSystemRights -Value $mockRightsResult -PassThru
            ) -PassThru |
            Add-Member -MemberType ScriptMethod -Name "SetAccessRule" -Value {} -PassThru |
            Add-Member -MemberType ScriptMethod -Name "RemoveAccessRule" -Value {} -PassThru
        }

        $mockGetCimAssociatedInstanceMSCluster_Resource = {
            return @(
                New-Object -TypeName Microsoft.Management.Infrastructure.CimInstance -ArgumentList 'MSCluster_Resource','root/MSCluster' |
                    Add-Member -MemberType NoteProperty -Name Name -Value $env:COMPUTERNAME -PassThru -Force
            )
        }

        $mockGetCimAssociatedInstanceMSCluster_ResourceToPossibleOwner = {
            return @(
                $ClusterNodes | ForEach-Object -Process {
                    $node = $_
                    New-Object -TypeName Microsoft.Management.Infrastructure.CimInstance -ArgumentList 'MSCluster_ResourceToPossibleOwner','root/MSCluster' |
                        Add-Member -MemberType NoteProperty -Name Name -Value $node -PassThru -Force
                }
            )
        }

        $mockGetCimInstanceMSCluster_Cluster = {
            return @(
                New-Object -TypeName Microsoft.Management.Infrastructure.CimInstance -ArgumentList 'MSCluster_Cluster','root/MSCluster' |
                    Add-Member -MemberType NoteProperty -Name Name -Value $mockClusterName -PassThru -Force
            )
        }

        $mockGetCimInstanceMSCluster_ClusterEmpty = {}

        $mockGetCimInstanceMSCluster_ClusterDiskPartition = {
            return @(
                New-Object -TypeName Microsoft.Management.Infrastructure.CimInstance -ArgumentList 'MSCluster_ClusterDiskPartition','root/MSCluster' |
                    Add-Member -MemberType NoteProperty -Name MountPoints -Value @($env:SystemDrive) -PassThru -Force
            )
        }

        $mockGetItem = {
            return New-Object -TypeName PsObject |
            Add-Member -MemberType ScriptMethod -Name GetAccessControl -Value {
                return New-Object -TypeName PsObject |
                Add-Member -MemberType NoteProperty -Name Access -Value @(
                    New-Object -TypeName PsObject |
                        Add-Member -MemberType NoteProperty -Name IdentityReference -Value $mockIdentity -PassThru |
                        Add-Member -MemberType NoteProperty -Name FileSystemRights -Value $mockRightsResult -PassThru
                ) -PassThru |
                Add-Member -MemberType ScriptMethod -Name "SetAccessRule" -Value {} -PassThru |
                Add-Member -MemberType ScriptMethod -Name "RemoveAccessRule" -Value {} -PassThru
            } -PassThru
        }

        $mockTestPath = {
            return $mockTestPathResult
        }
        #endregion Cmdlet Mocks

        #region Test Cases
        $getTargetResourceTestCasesPathExists = @(
            @{
                Path = $mockPath
                Identity = $mockIdentity
                RightsResult = $mockRights
                IsActiveNodeResult = $true
                ClusterNodes = $mockClusterNodes
            }
            @{
                Path = $mockPath
                Identity = 'contoso\bob'
                RightsResult = @()
                IsActiveNodeResult = $true
                ClusterNodes = $mockClusterNodes
            }
            @{
                Path = $mockPath
                Identity = $mockIdentity
                RightsResult = @()
                IsActiveNodeResult = $false
                ClusterNodes = $mockClusterNodes
            }
        )

        $getTargetResourceTestCasesPathDoesNotExist = @(
            @{
                Path = $mockPath
                Identity = $mockIdentity
                RightsResult = $mockRights
                IsActiveNodeResult = $false
                ClusterNodes = $mockClusterNodes
                MSCluster_ClusterMock = $mockGetCimInstanceMSCluster_ClusterEmpty
            }
            @{
                Path = $mockPath
                Identity = $mockIdentity
                RightsResult = $mockRights
                IsActiveNodeResult = $false
                ClusterNodes = ( $mockClusterNodes | Where-Object -FilterScript { $_ -ne $env:COMPUTERNAME } )
                MSCluster_ClusterMock = $mockGetCimInstanceMSCluster_Cluster
            }
        )

        $setTargetResourceTestCasesAbsent = @(
            @{
                Path = $mockPath
                Identity = $mockIdentity
                Rights = $mockRights
                Ensure = 'Absent'
                ProcessOnlyOnActiveNode = $false
            }
        )

        $setTargetResourceTestCasesPresent = @(
            @{
                Path = $mockPath
                Identity = $mockIdentity
                Rights = $mockRights
                Ensure = 'Present'
                ProcessOnlyOnActiveNode = $false
            }
        )

        $testTargetResourceTestCasesAbsent = @(
            @{
                Path = $mockPath
                Identity = $mockIdentity
                Rights = $null
                Ensure = 'Absent'
                ProcessOnlyOnActiveNode = $false
                TestResult = $false         # Per discussion with Johlju the previous behavior was non-intuitive, and this case implies all ACL permissions should be removed, not a silent pass.
                ClusterNodes = $mockClusterNodes
            }
            @{
                Path = $mockPath
                Identity = $mockIdentity
                Rights = @('FullControl')
                Ensure = 'Absent'
                ProcessOnlyOnActiveNode = $false
                TestResult = $true
                ClusterNodes = $mockClusterNodes
            }
            @{
                Path = $mockPath
                Identity = $mockIdentity
                Rights = $mockRights
                Ensure = 'Absent'
                ProcessOnlyOnActiveNode = $false
                TestResult = $false
                ClusterNodes = $mockClusterNodes
            }
            @{
                Path = $mockPath
                Identity = $mockIdentity
                Rights = $mockRights
                Ensure = 'Absent'
                ProcessOnlyOnActiveNode = $true
                TestResult = $true
                ClusterNodes = $mockClusterNodes
            }
        )

        $testTargetResourceTestCasesPresent = @(
            @{
                Path = $mockPath
                Identity = $mockIdentity
                Rights = @('FullControl')
                Ensure = 'Present'
                ProcessOnlyOnActiveNode = $false
                TestResult = $false
                ClusterNodes = $mockClusterNodes
            }
            @{
                Path = $mockPath
                Identity = $mockIdentity
                Rights = $mockRights
                Ensure = 'Present'
                ProcessOnlyOnActiveNode = $false
                TestResult = $true
                ClusterNodes = $mockClusterNodes
            }
            @{
                Path = $mockPath
                Identity = $mockIdentity
                Rights = $mockRights
                Ensure = 'Present'
                ProcessOnlyOnActiveNode = $true
                TestResult = $true
                ClusterNodes = $mockClusterNodes
            }
        )

        $testTargetResourceTestCasesPresentError = @(
            @{
                Path = $mockPath
                Identity = $mockIdentity
                Ensure = 'Present'
                ProcessOnlyOnActiveNode = $false
                TestResult = $false
                ClusterNodes = $mockClusterNodes
            }
        )
        #endregion Test Cases

        Describe 'MSFT_xFileSystemAccessRule\Get-TargetResource' -Tag Get {
            BeforeAll {
                Mock -CommandName Get-Acl -MockWith $mockGetAcl -Verifiable
                Mock -CommandName Get-CimAssociatedInstance -MockWith $mockGetCimAssociatedInstanceMSCluster_Resource -Verifiable -ParameterFilter { $ResultClassName -eq 'MSCluster_Resource' }
                Mock -CommandName Get-CimAssociatedInstance -MockWith $mockGetCimAssociatedInstanceMSCluster_ResourceToPossibleOwner -Verifiable -ParameterFilter { $Association -eq 'MSCluster_ResourceToPossibleOwner' }
                Mock -CommandName Get-CimInstance -MockWith $mockGetCimInstanceMSCluster_ClusterDiskPartition -Verifiable -ParameterFilter { $ClassName -eq 'MSCluster_ClusterDiskPartition' }
                Mock -CommandName Test-Path -MockWith $mockTestPath -Verifiable
            }

            Context 'When the specified path exists' {
                BeforeAll {
                    Mock -CommandName Get-CimInstance -MockWith $mockGetCimInstanceMSCluster_Cluster -Verifiable -ParameterFilter { $ClassName -eq 'MSCluster_Cluster' }
                }

                BeforeEach {
                    $mockTestPathResult = $true
                }

                It 'Should obtain the current values for the Path "<Path>" when Identity is "<Identity>" and IsActiveNode is "<IsActiveNodeResult>"' -TestCases $getTargetResourceTestCasesPathExists {
                    Param
                    (
                        $Path,
                        $Identity,
                        $RightsResult,
                        $IsActiveNodeResult,
                        $ClusterNodes
                    )

                    $mockTestPathResult = $IsActiveNodeResult

                    if ( $IsActiveNodeResult )
                    {
                        $assertMockCalledGetAcl = 1
                        $assertMockCalledGetCimAssociatedInstance = 0
                        $assertMockCalledGetCimInstance = 0
                    }
                    else
                    {
                        $assertMockCalledGetAcl = 0
                        $assertMockCalledGetCimAssociatedInstance = 1
                        $assertMockCalledGetCimInstance = 1
                    }

                    $getTargetResourceParameters = @{
                        Path = $Path
                        Identity = $Identity
                   }

                    $getTargetResourceResult = Get-TargetResource @getTargetResourceParameters

                    $getTargetResourceResult.Path | Should -Be $Path
                    $getTargetResourceResult.Identity | Should -Be $Identity
                    $getTargetResourceResult.Rights | Should -Be $RightsResult
                    $getTargetResourceResult.IsActiveNode | Should -Be $IsActiveNodeResult

                    Assert-MockCalled -CommandName Get-Acl -Times $assertMockCalledGetAcl -Exactly -Scope It
                    Assert-MockCalled -CommandName Get-CimAssociatedInstance -Times $assertMockCalledGetCimAssociatedInstance -Exactly -Scope It -ParameterFilter { $ResultClassName -eq 'MSCluster_Resource' }
                    Assert-MockCalled -CommandName Get-CimAssociatedInstance -Times $assertMockCalledGetCimAssociatedInstance -Exactly -Scope It -ParameterFilter { $Association -eq 'MSCluster_ResourceToPossibleOwner' }
                    Assert-MockCalled -CommandName Get-CimInstance -Times $assertMockCalledGetCimInstance -Exactly -Scope It -ParameterFilter { $ClassName -eq 'MSCluster_Cluster' }
                    Assert-MockCalled -CommandName Get-CimInstance -Times $assertMockCalledGetCimInstance -Exactly -Scope It -ParameterFilter { $ClassName -eq 'MSCluster_ClusterDiskPartition' }
                    Assert-MockCalled -CommandName Test-Path -Times 1 -Exactly -Scope It
                }
            }

            Context 'When the specified path does not exist' {
                BeforeEach {
                    $mockTestPathResult = $false
                }

                It 'Should throw the correct error when IsActiveNode is "<IsActiveNodeResult>" and the available cluster nodes are "<ClusterNodes>"' -TestCases $getTargetResourceTestCasesPathDoesNotExist {
                    Param
                    (
                        $Path,
                        $Identity,
                        $RightsResult,
                        $IsActiveNodeResult,
                        $ClusterNodes,
                        $MSCluster_ClusterMock
                    )

                    Mock -CommandName Get-CimInstance -MockWith $MSCluster_ClusterMock -Verifiable -ParameterFilter { $ClassName -eq 'MSCluster_Cluster' }

                    if ( $ClusterNodes -contains $env:COMPUTERNAME )
                    {
                        $assertMockCalledGetCimAssociatedInstance = 0
                        $assertMockCalledGetCimInstanceMSCluster_ClusterDiskPartition = 0
                    }
                    else
                    {
                        $assertMockCalledGetCimAssociatedInstance = 1
                        $assertMockCalledGetCimInstanceMSCluster_ClusterDiskPartition = 1
                    }

                    $getTargetResourceParameters = @{
                        Path = $Path
                        Identity = $Identity
                   }

                    { Get-TargetResource @getTargetResourceParameters } | Should -Throw "Unable to get ACL for '$Path' because it does not exist"

                    Assert-MockCalled -CommandName Get-Acl -Times 0 -Exactly -Scope It
                    Assert-MockCalled -CommandName Get-CimAssociatedInstance -Times $assertMockCalledGetCimAssociatedInstance -Exactly -Scope It -ParameterFilter { $ResultClassName -eq 'MSCluster_Resource' }
                    Assert-MockCalled -CommandName Get-CimAssociatedInstance -Times $assertMockCalledGetCimAssociatedInstance -Exactly -Scope It -ParameterFilter { $Association -eq 'MSCluster_ResourceToPossibleOwner' }
                    Assert-MockCalled -CommandName Get-CimInstance -Times 1 -Exactly -Scope It -ParameterFilter { $ClassName -eq 'MSCluster_Cluster' }
                    Assert-MockCalled -CommandName Get-CimInstance -Times $assertMockCalledGetCimInstanceMSCluster_ClusterDiskPartition -Exactly -Scope It -ParameterFilter { $ClassName -eq 'MSCluster_ClusterDiskPartition' }
                    Assert-MockCalled -CommandName Test-Path -Times 1 -Exactly -Scope It
                }
            }
        }

        Describe 'MSFT_xFileSystemAccessRule\Set-TargetResource' -Tag Set {
            BeforeAll {
                Mock -CommandName Get-Item -MockWith $mockGetItem -Verifiable
                Mock -CommandName Set-Acl -MockWith {} -Verifiable
                Mock -CommandName Test-Path -MockWith $mockTestPath -Verifiable
            }

            BeforeEach {
                $mockTestPathResult = $true
            }

            Context 'When the desired state is Absent' {
                It 'Should remove the rights "<Rights>" for the identity "<Identity>" when the desired state is "<Ensure>"' -TestCases $setTargetResourceTestCasesAbsent {
                    param
                    (
                        $Path,
                        $Identity,
                        $Rights,
                        $Ensure,
                        $ProcessOnlyOnActiveNode
                    )

                    $setTargetResourceParameters = @{
                        Path = $Path
                        Identity = $Identity
                        Rights = $Rights
                        Ensure = $Ensure
                        ProcessOnlyOnActiveNode = $ProcessOnlyOnActiveNode
                    }

                    { Set-TargetResource @setTargetResourceParameters } | Should -Not -Throw

                    Assert-MockCalled -CommandName Get-Item -Times 1 -Exactly -Scope It
                    Assert-MockCalled -CommandName Set-Acl -Times 1 -Exactly -Scope It
                    Assert-MockCalled -CommandName Test-Path -Times 1 -Exactly -Scope It
                }

                It 'Should throw the correct error when the path "<Path>" does not exist' -TestCases $setTargetResourceTestCasesAbsent {
                    param
                    (
                        $Path,
                        $Identity,
                        $Rights,
                        $Ensure,
                        $ProcessOnlyOnActiveNode
                    )

                    $mockTestPathResult = $false

                    $setTargetResourceParameters = @{
                        Path = $Path
                        Identity = $Identity
                        Rights = $Rights
                        Ensure = $Ensure
                        ProcessOnlyOnActiveNode = $ProcessOnlyOnActiveNode
                    }

                    { Set-TargetResource @setTargetResourceParameters } | Should -Throw "The path '$Path' does not exist"

                    Assert-MockCalled -CommandName Get-Item -Times 0 -Exactly -Scope It
                    Assert-MockCalled -CommandName Set-Acl -Times 0 -Exactly -Scope It
                    Assert-MockCalled -CommandName Test-Path -Times 1 -Exactly -Scope It
                }
            }

            Context 'When the desired state is Present' {
                It 'Should add the rights "<Rights>" for the identity "<Identity>" when the desired state is "<Ensure>"' -TestCases $setTargetResourceTestCasesPresent {
                    param
                    (
                        $Path,
                        $Identity,
                        $Rights,
                        $Ensure,
                        $ProcessOnlyOnActiveNode
                    )

                    $setTargetResourceParameters = @{
                        Path = $Path
                        Identity = $Identity
                        Rights = $Rights
                        Ensure = $Ensure
                        ProcessOnlyOnActiveNode = $ProcessOnlyOnActiveNode
                    }

                    { Set-TargetResource @setTargetResourceParameters } | Should -Not -Throw

                    Assert-MockCalled -CommandName Get-Item -Times 1 -Exactly -Scope It
                    Assert-MockCalled -CommandName Set-Acl -Times 1 -Exactly -Scope It
                    Assert-MockCalled -CommandName Test-Path -Times 1 -Exactly -Scope It
                }

                It 'Should throw the correct error when the path "<Path>" does not exist' -TestCases $setTargetResourceTestCasesPresent {
                    param
                    (
                        $Path,
                        $Identity,
                        $Rights,
                        $Ensure,
                        $ProcessOnlyOnActiveNode
                    )

                    $mockTestPathResult = $false

                    $setTargetResourceParameters = @{
                        Path = $Path
                        Identity = $Identity
                        Rights = $Rights
                        Ensure = $Ensure
                        ProcessOnlyOnActiveNode = $ProcessOnlyOnActiveNode
                    }

                    { Set-TargetResource @setTargetResourceParameters } | Should -Throw "The path '$Path' does not exist"

                    Assert-MockCalled -CommandName Get-Item -Times 0 -Exactly -Scope It
                    Assert-MockCalled -CommandName Set-Acl -Times 0 -Exactly -Scope It
                    Assert-MockCalled -CommandName Test-Path -Times 1 -Exactly -Scope It
                }

                It 'Should throw the correct error when the Rights parameter is not supplied' -TestCases $setTargetResourceTestCasesPresent {
                    param
                    (
                        $Path,
                        $Identity,
                        $Rights,
                        $Ensure,
                        $ProcessOnlyOnActiveNode
                    )

                    $setTargetResourceParameters = @{
                        Path = $Path
                        Identity = $Identity
                        Ensure = $Ensure
                        ProcessOnlyOnActiveNode = $ProcessOnlyOnActiveNode
                    }

                    { Set-TargetResource @setTargetResourceParameters } | Should -Throw "No rights were specified for '$Identity' on '$Path'"

                    Assert-MockCalled -CommandName Get-Item -Times 1 -Exactly -Scope It
                    Assert-MockCalled -CommandName Set-Acl -Times 0 -Exactly -Scope It
                    Assert-MockCalled -CommandName Test-Path -Times 1 -Exactly -Scope It
                }
            }
        }

        Describe 'MSFT_xFileSystemAccessRule\Test-TargetResource' -Tag Test {
            BeforeAll {
                Mock -CommandName Get-Acl -MockWith $mockGetAcl -Verifiable
                Mock -CommandName Get-CimAssociatedInstance -MockWith $mockGetCimAssociatedInstanceMSCluster_Resource -Verifiable -ParameterFilter { $ResultClassName -eq 'MSCluster_Resource' }
                Mock -CommandName Get-CimAssociatedInstance -MockWith $mockGetCimAssociatedInstanceMSCluster_ResourceToPossibleOwner -Verifiable -ParameterFilter { $Association -eq 'MSCluster_ResourceToPossibleOwner' }
                Mock -CommandName Get-CimInstance -MockWith $mockGetCimInstanceMSCluster_Cluster -Verifiable -ParameterFilter { $ClassName -eq 'MSCluster_Cluster' }
                Mock -CommandName Get-CimInstance -MockWith $mockGetCimInstanceMSCluster_ClusterDiskPartition -Verifiable -ParameterFilter { $ClassName -eq 'MSCluster_ClusterDiskPartition' }
                Mock -CommandName Test-Path -MockWith $mockTestPath -Verifiable
            }

            Context 'When the desired state is Absent' {
                BeforeEach {
                    $mockTestPathResult = $true
                }

                It 'Should be "<TestResult>" when the specified Rights are "<Rights>"' -TestCases $testTargetResourceTestCasesAbsent {
                    param
                    (
                        $Path,
                        $Identity,
                        $Rights,
                        $Ensure,
                        $ProcessOnlyOnActiveNode,
                        $TestResult,
                        $ClusterNodes
                    )

                    if ( $ProcessOnlyOnActiveNode )
                    {
                        $mockTestPathResult = $false
                        $assertMockCalledGetAcl = 0
                        $assertMockCalledGetCimAssociatedInstance = 1
                        $assertMockCalledGetCimInstance = 1
                    }
                    else
                    {
                        $assertMockCalledGetAcl = 1
                        $assertMockCalledGetCimAssociatedInstance = 0
                        $assertMockCalledGetCimInstance = 0
                    }

                    $testTargetResourceParameters = @{
                        Path = $Path
                        Identity = $Identity
                        Ensure = $Ensure
                        ProcessOnlyOnActiveNode = $ProcessOnlyOnActiveNode
                    }

                    if ( $Rights )
                    {
                        $testTargetResourceParameters.Add('Rights',$Rights)
                    }

                    Test-TargetResource @testTargetResourceParameters | Should -Be $TestResult

                    Assert-MockCalled -CommandName Get-Acl -Times $assertMockCalledGetAcl -Exactly -Scope It
                    Assert-MockCalled -CommandName Get-CimAssociatedInstance -Times $assertMockCalledGetCimAssociatedInstance -Exactly -Scope It -ParameterFilter { $ResultClassName -eq 'MSCluster_Resource' }
                    Assert-MockCalled -CommandName Get-CimAssociatedInstance -Times $assertMockCalledGetCimAssociatedInstance -Exactly -Scope It -ParameterFilter { $Association -eq 'MSCluster_ResourceToPossibleOwner' }
                    Assert-MockCalled -CommandName Get-CimInstance -Times $assertMockCalledGetCimInstance -Exactly -Scope It -ParameterFilter { $ClassName -eq 'MSCluster_Cluster' }
                    Assert-MockCalled -CommandName Get-CimInstance -Times $assertMockCalledGetCimInstance -Exactly -Scope It -ParameterFilter { $ClassName -eq 'MSCluster_ClusterDiskPartition' }
                    Assert-MockCalled -CommandName Test-Path -Times 1 -Exactly -Scope It
                }
            }

            Context 'When the desired state is Present' {
                It 'Should be "<TestResult>" when the specified Rights are "<Rights>"' -TestCases $testTargetResourceTestCasesPresent {
                    param
                    (
                        $Path,
                        $Identity,
                        $Rights,
                        $Ensure,
                        $ProcessOnlyOnActiveNode,
                        $TestResult,
                        $ClusterNodes
                    )

                    if ( $ProcessOnlyOnActiveNode )
                    {
                        $mockTestPathResult = $false
                        $assertMockCalledGetAcl = 0
                        $assertMockCalledGetCimAssociatedInstance = 1
                        $assertMockCalledGetCimInstance = 1
                    }
                    else
                    {
                        $assertMockCalledGetAcl = 1
                        $assertMockCalledGetCimAssociatedInstance = 0
                        $assertMockCalledGetCimInstance = 0
                    }

                    $testTargetResourceParameters = @{
                        Path = $Path
                        Identity = $Identity
                        Rights = $Rights
                        Ensure = $Ensure
                        ProcessOnlyOnActiveNode = $ProcessOnlyOnActiveNode
                    }

                    Test-TargetResource @testTargetResourceParameters | Should -Be $TestResult

                    Assert-MockCalled -CommandName Get-Acl -Times $assertMockCalledGetAcl -Exactly -Scope It
                    Assert-MockCalled -CommandName Get-CimAssociatedInstance -Times $assertMockCalledGetCimAssociatedInstance -Exactly -Scope It -ParameterFilter { $ResultClassName -eq 'MSCluster_Resource' }
                    Assert-MockCalled -CommandName Get-CimAssociatedInstance -Times $assertMockCalledGetCimAssociatedInstance -Exactly -Scope It -ParameterFilter { $Association -eq 'MSCluster_ResourceToPossibleOwner' }
                    Assert-MockCalled -CommandName Get-CimInstance -Times $assertMockCalledGetCimInstance -Exactly -Scope It -ParameterFilter { $ClassName -eq 'MSCluster_Cluster' }
                    Assert-MockCalled -CommandName Get-CimInstance -Times $assertMockCalledGetCimInstance -Exactly -Scope It -ParameterFilter { $ClassName -eq 'MSCluster_ClusterDiskPartition' }
                    Assert-MockCalled -CommandName Test-Path -Times 1 -Exactly -Scope It
                }

                It 'Should throw the correct error when the Rights parameter is not supplied' -TestCases $testTargetResourceTestCasesPresentError {
                    param
                    (
                        $Path,
                        $Identity,
                        $Ensure,
                        $ProcessOnlyOnActiveNode,
                        $TestResult,
                        $ClusterNodes
                    )

                    if ( $ProcessOnlyOnActiveNode )
                    {
                        $mockTestPathResult = $false
                        $assertMockCalledGetAcl = 0
                        $assertMockCalledGetCimAssociatedInstance = 1
                        $assertMockCalledGetCimInstance = 1
                    }
                    else
                    {
                        $assertMockCalledGetAcl = 1
                        $assertMockCalledGetCimAssociatedInstance = 0
                        $assertMockCalledGetCimInstance = 0
                    }

                    $testTargetResourceParameters = @{
                        Path = $Path
                        Identity = $Identity
                        Ensure = $Ensure
                        ProcessOnlyOnActiveNode = $ProcessOnlyOnActiveNode
                    }

                    { Test-TargetResource @testTargetResourceParameters } | Should -Throw "No rights were specified for '$Identity' on '$Path'"

                    Assert-MockCalled -CommandName Get-Acl -Times $assertMockCalledGetAcl -Exactly -Scope It
                    Assert-MockCalled -CommandName Get-CimAssociatedInstance -Times $assertMockCalledGetCimAssociatedInstance -Exactly -Scope It -ParameterFilter { $ResultClassName -eq 'MSCluster_Resource' }
                    Assert-MockCalled -CommandName Get-CimAssociatedInstance -Times $assertMockCalledGetCimAssociatedInstance -Exactly -Scope It -ParameterFilter { $Association -eq 'MSCluster_ResourceToPossibleOwner' }
                    Assert-MockCalled -CommandName Get-CimInstance -Times $assertMockCalledGetCimInstance -Exactly -Scope It -ParameterFilter { $ClassName -eq 'MSCluster_Cluster' }
                    Assert-MockCalled -CommandName Get-CimInstance -Times $assertMockCalledGetCimInstance -Exactly -Scope It -ParameterFilter { $ClassName -eq 'MSCluster_ClusterDiskPartition' }
                    Assert-MockCalled -CommandName Test-Path -Times 1 -Exactly -Scope It
                }
            }
        }

        Describe 'MSFT_xFileSystemAccessRule\Get-AclAccess' -Tag Helper {
            BeforeAll {
                Mock -CommandName Get-Item -MockWith $mockGetItem -Verifiable
            }

            Context 'When the function is called' {
                It 'Should return the ACL' {
                    $result = Get-AclAccess -Path $mockPath

                    $result.Access[0].IdentityReference | Should -Be $mockIdentity
                    $result.Access[0].FileSystemRights | Should -Be $mockRightsResult

                    Assert-MockCalled -CommandName Get-Item -Times 1 -Exactly -Scope It
                }
            }
        }
    }
}
finally
{
    Invoke-TestCleanup
}


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
                $testIdentity = (Get-LocalGroup | Select-Object -First 1).Name
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
