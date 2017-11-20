function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])] 
    param(
        [Parameter(Mandatory = $true)]
        [String]
        $Path,

        [Parameter(Mandatory = $true)]
        [String]
        $Identity,

        [Parameter()]
        [String[]]
        [ValidateSet("ListDirectory",
                     "ReadData",
                     "WriteData",
                     "CreateFiles",
                     "CreateDirectories",
                     "AppendData",
                     "ReadExtendedAttributes",
                     "WriteExtendedAttributes",
                     "Traverse",
                     "ExecuteFile",
                     "DeleteSubdirectoriesAndFiles",
                     "ReadAttributes",
                     "WriteAttributes",
                     "Write",
                     "Delete",
                     "ReadPermissions",
                     "Read",
                     "ReadAndExecute",
                     "Modify",
                     "ChangePermissions",
                     "TakeOwnership",
                     "Synchronize",
                     "FullControl")]
        $Rights,

        [Parameter()]
        [String]
        [ValidateSet('Present','Absent')]
        $Ensure = 'Present'
    )

    $result = @{
        Path = $Path
        Identity = $Identity
        Rights = @()
        Ensure = 'Present'
        IsActiveNode = $true
    }
    
    if ( -not ( Test-Path -Path $Path ) )
    {
        $isClusterResource = $false

        # Is the node a member of a WSFC?
        $msCluster = Get-CimInstance -Namespace root/MSCluster -ClassName MSCluster_Cluster -ErrorAction SilentlyContinue

        if ( $msCluster )
        {
            # Is the defined path built off of a known mount point in the cluster?
            $clusterPartition = Get-CimInstance -Namespace root/MSCluster -ClassName MSCluster_ClusterDiskPartition | Where-Object -FilterScript {
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
            if ( $possibleOwners -notcontains $env:COMPUTERNAME )
            {
                Write-Verbose -Message "'$($env:COMPUTERNAME)' is not a possible owner for '$Path'."
            }
            else
            {
                $isClusterResource = $true
            }
        }

        if ( -not $isClusterResource )
        {
            throw "Unable to get ACL for '$Path' as it does not exist"
        }
        else
        {
            $result.IsActiveNode = $false
        }
    }
    else
    {
        $acl = Get-Acl -Path $Path
        $accessRules = $acl.Access

        $identityRule = $accessRules | Select-Object -ExpandProperty FileSystemRights -Unique

        if ($null -eq $identityRule)
        {
            $result.Ensure = 'Absent'
        }
        else
        {
            $result.Rights = $identityRule
        }
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
        [ValidateSet("ListDirectory",
                     "ReadData",
                     "WriteData",
                     "CreateFiles",
                     "CreateDirectories",
                     "AppendData",
                     "ReadExtendedAttributes",
                     "WriteExtendedAttributes",
                     "Traverse",
                     "ExecuteFile",
                     "DeleteSubdirectoriesAndFiles",
                     "ReadAttributes",
                     "WriteAttributes",
                     "Write",
                     "Delete",
                     "ReadPermissions",
                     "Read",
                     "ReadAndExecute",
                     "Modify",
                     "ChangePermissions",
                     "TakeOwnership",
                     "Synchronize",
                     "FullControl")]
        $Rights,

        [Parameter()]
        [String]
        [ValidateSet("Present","Absent")]
        $Ensure = "Present",

        [Parameter()]
        [Boolean]
        $ProcessOnlyOnActiveNode
    )

    if ((Test-Path -Path $Path) -eq $false)
    {
        throw "Unable to get ACL for '$Path' as it does not exist"
    }

    $acl = Get-ACLAccess -Path $Path
    $accessRules = $acl.Access

    if ($Ensure -eq "Present")
    {
        Write-Verbose -Message "Setting access rules for $Identity on $Path"
        $newRights = [System.Security.AccessControl.FileSystemRights]$Rights
        $ar = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                         -ArgumentList @(
                                $Identity, 
                                $newRights, 
                                "ContainerInherit,ObjectInherit", 
                                "None", 
                                "Allow")
        $acl.SetAccessRule($ar)

        Set-Acl -Path $Path -AclObject $acl

    }

    if ($Ensure -eq "Absent")
    {
        $identityRule = $accessRules | Where-Object -FilterScript {
            $_.IdentityReference -eq $Identity
        } | Select-Object -First 1

        if ($null -ne $identityRule)
        {
            Write-Verbose -Message "Removing access rules for $Identity on $Path"
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
        [ValidateSet("ListDirectory",
                     "ReadData",
                     "WriteData",
                     "CreateFiles",
                     "CreateDirectories",
                     "AppendData",
                     "ReadExtendedAttributes",
                     "WriteExtendedAttributes",
                     "Traverse",
                     "ExecuteFile",
                     "DeleteSubdirectoriesAndFiles",
                     "ReadAttributes",
                     "WriteAttributes",
                     "Write",
                     "Delete",
                     "ReadPermissions",
                     "Read",
                     "ReadAndExecute",
                     "Modify",
                     "ChangePermissions",
                     "TakeOwnership",
                     "Synchronize",
                     "FullControl")]
        $Rights,

        [Parameter()]
        [String]
        [ValidateSet("Present","Absent")]
        $Ensure = "Present",
        
        [Parameter()]
        [Boolean]
        $ProcessOnlyOnActiveNode
    )

    $currentValues = Get-TargetResource @PSBoundParameters

    <#
        If this is supposed to process on the active node, and this is not the
        active node, don't bother evaluating the test.
    #>
    if ( $ProcessOnlyOnActiveNode -and -not $currentValues.IsActiveNode )
    {
        Write-Verbose -Message ( 'The node "{0}" is not actively hosting the path "{1}". Exiting the test.' -f $env:COMPUTERNAME,$Path )
        return $true
    }

    if ($null -eq $currentValues) 
    {
        throw "Unable to determine current ACL values for '$Path'"
    }

    if ($currentValues.Ensure -ne $Ensure)
    {
        Write-Verbose -Message "Ensure property does not match"
        return $false
    }

    if ($Ensure -eq "Present")
    {
        $rightsCompare = Compare-Object -ReferenceObject $currentValues.Rights -DifferenceObject $Rights
        if ($null -ne $rightsCompare)
        {
            Write-Verbose -Message "Rights property does not match"
            return $false
        }
    }

    return $true
}
 Function Get-ACLAccess($Path)
{
    return (Get-Item -Path $Path).GetAccessControl('Access')
}

Export-ModuleMember -Function *-TargetResource
