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
        $mockTestPathResult = $true
        #endregion Mock Variables

        #region Cmdlet Mocks
        $mockGetAcl = { 
            return New-Object -TypeName PsObject |
            Add-Member -MemberType NoteProperty -Name Access -Value @(
                New-Object -TypeName PsObject |
                    Add-Member -MemberType NoteProperty -Name IdentityReference -Value $mockIdentity -PassThru |
                    Add-Member -MemberType NoteProperty -Name FileSystemRights -Value $mockRights -PassThru
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
                        Add-Member -MemberType NoteProperty -Name FileSystemRights -Value $mockRights -PassThru
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
                TestResult = $true
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
                    $result.Access[0].FileSystemRights | Should -Be $mockRights

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
