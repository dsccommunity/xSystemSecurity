function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])] 
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $Path,

        [Parameter(Mandatory = $true)]
        [String]
        $Identity
    )

    $result = @{
        Path = $Path
        Identity = $Identity
        Rights = @()
        IsActiveNode = $true
    }
    
    if ( -not ( Test-Path -Path $Path ) )
    {
        $isClusterResource = $false

        # Is the node a member of a WSFC?
        $msCluster = Get-CimInstance -Namespace root/MSCluster -ClassName MSCluster_Cluster -ErrorAction SilentlyContinue

        if ( $msCluster )
        {
            Write-Verbose -Message "$($env:COMPUTERNAME) is a member of the Windows Server Failover Cluster '$($msCluster.Name)'" -Verbose
            
            # Is the defined path built off of a known mount point in the cluster?
            $clusterPartition = Get-CimInstance -Namespace root/MSCluster -ClassName MSCluster_ClusterDiskPartition |
                Where-Object -FilterScript {
                    $currentPartition = $_

                    $currentPartition.MountPoints | ForEach-Object -Process {
                        [regex]::Escape($Path) -match "^$($_)"
                    }
                }

            # Get the possible owner nodes for the partition
            [array]$possibleOwners = $clusterPartition |
                Get-CimAssociatedInstance -ResultClassName 'MSCluster_Resource' |
                    Get-CimAssociatedInstance -Association 'MSCluster_ResourceToPossibleOwner' | 
                        Select-Object -ExpandProperty Name -Unique
            
            # Ensure the current node is a possible owner of the drive
            if ( $possibleOwners -contains $env:COMPUTERNAME )
            {
                $isClusterResource = $true                
                $result.IsActiveNode = $false
            }
            else
            {
                Write-Verbose -Message "'$($env:COMPUTERNAME)' is not a possible owner for '$Path'." -Verbose
            }
        }

        if ( -not $isClusterResource )
        {
            throw "Unable to get ACL for '$Path' because it does not exist"
        }
    }
    else
    {
        $acl = Get-Acl -Path $Path
        $accessRules = $acl.Access

        $result.Rights = @(
            $accessRules |
                Where-Object -FilterScript { $_.IdentityReference -eq $Identity } |
                Select-Object -ExpandProperty FileSystemRights -Unique
        )
    }
    return $result
}

function Set-TargetResource
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [String]
        $Path,

        [Parameter(Mandatory = $true)]
        [String]
        $Identity,

        [Parameter()]
        [String[]]
        [ValidateSet('ListDirectory',
                     'ReadData',
                     'WriteData',
                     'CreateFiles',
                     'CreateDirectories',
                     'AppendData',
                     'ReadExtendedAttributes',
                     'WriteExtendedAttributes',
                     'Traverse',
                     'ExecuteFile',
                     'DeleteSubdirectoriesAndFiles',
                     'ReadAttributes',
                     'WriteAttributes',
                     'Write',
                     'Delete',
                     'ReadPermissions',
                     'Read',
                     'ReadAndExecute',
                     'Modify',
                     'ChangePermissions',
                     'TakeOwnership',
                     'Synchronize',
                     'FullControl')]
        $Rights = @(),

        [Parameter()]
        [String]
        [ValidateSet('Present','Absent')]
        $Ensure = 'Present',

        [Parameter()]
        [Boolean]
        $ProcessOnlyOnActiveNode
    )

    if ( -not ( Test-Path -Path $Path ) )
    {
        throw ( "The path '$Path' does not exist." )
    }

    $acl = Get-ACLAccess -Path $Path
    $accessRules = $acl.Access

    if ( $Ensure -eq 'Present' )
    {
        Write-Verbose -Message "Setting access rules for '$Identity' on '$Path'" -Verbose

        $newFileSystemAccessRuleParameters = @{
            TypeName = 'System.Security.AccessControl.FileSystemAccessRule'
            ArgumentList = @(
                $Identity, 
                [System.Security.AccessControl.FileSystemRights]$Rights, 
                'ContainerInherit,ObjectInherit', 
                'None', 
                'Allow'
            )
        }

        $ar = New-Object @newFileSystemAccessRuleParameters
        $acl.SetAccessRule($ar)

        Set-Acl -Path $Path -AclObject $acl
    }

    if ($Ensure -eq 'Absent')
    {
        $identityRule = $accessRules | Where-Object -FilterScript {
            $_.IdentityReference -eq $Identity
        } | Select-Object -First 1

        if ( $null -ne $identityRule )
        {
            Write-Verbose -Message "Removing access rules for '$Identity' on '$Path'" -Verbose
            $acl.RemoveAccessRule($identityRule) | Out-Null
            Set-Acl -Path $Path -AclObject $acl
        }
    }
}

function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])] 
    param(
        [Parameter(Mandatory = $true)]
        [String]
        $Path,

        [Parameter(Mandatory = $true)]
        [String]
        $Identity,

        [Parameter()]
        [String[]]
        [ValidateSet('ListDirectory',
                     'ReadData',
                     'WriteData',
                     'CreateFiles',
                     'CreateDirectories',
                     'AppendData',
                     'ReadExtendedAttributes',
                     'WriteExtendedAttributes',
                     'Traverse',
                     'ExecuteFile',
                     'DeleteSubdirectoriesAndFiles',
                     'ReadAttributes',
                     'WriteAttributes',
                     'Write',
                     'Delete',
                     'ReadPermissions',
                     'Read',
                     'ReadAndExecute',
                     'Modify',
                     'ChangePermissions',
                     'TakeOwnership',
                     'Synchronize',
                     'FullControl')]
        $Rights = @(),

        [Parameter()]
        [String]
        [ValidateSet('Present','Absent')]
        $Ensure = 'Present',
        
        [Parameter()]
        [Boolean]
        $ProcessOnlyOnActiveNode
    )

    $result = $true

    $getTargetResourceParameters = @{
        Path = $Path
        Identity = $Identity
    }
    
    $currentValues = Get-TargetResource @getTargetResourceParameters

    <#
        If this is supposed to process on the active node, and this is not the
        active node, don't bother evaluating the test.
    #>
    if ( $ProcessOnlyOnActiveNode -and -not $currentValues.IsActiveNode )
    {
        Write-Verbose -Message ( 'The node "{0}" is not actively hosting the path "{1}". Exiting the test.' -f $env:COMPUTERNAME,$Path ) -Verbose
        return $result
    }

    switch ( $Ensure )
    {
        'Absent'
        {
            # If the right is defined and currently set, return it
            $comparisonResult = Compare-Object -ReferenceObject $Rights -DifferenceObject $currentValues.Rights -ExcludeDifferent -IncludeEqual |
                Select-Object -ExpandProperty InputObject
        }
        
        'Present'
        {
            # If the right is defined and missing, return it
            $comparisonResult = Compare-Object -ReferenceObject $Rights -DifferenceObject $currentValues.Rights |
                Where-Object -FilterScript { $_.SideIndicator -eq '<=' } |
                Select-Object -ExpandProperty InputObject
        }
    }

    # If results were found from the comparison
    if ( $comparisonResult.Count -gt 0 )
    {
        Write-Verbose -Message ( 'The identity "{0}" has the rights "{1}".' -f $Identity,( $currentValues.Rights -join ', ' ) ) -Verbose
        $result = $false
    }

    return $result
}
 Function Get-ACLAccess($Path)
{
    return (Get-Item -Path $Path).GetAccessControl('Access')
}

Export-ModuleMember -Function *-TargetResource
