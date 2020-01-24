# I'm quickly hacking my local test case file into pester tests that should probably not be run as part of a build. Assumes Set is working, and test order matters.
. $PSScriptRoot\..\..\DSCResources\MSFT_xFileSystemAccessRule\MSFT_xFileSystemAccessRule.psm1

Describe "Test the Set and Test (and Get, by extension) functionality of MSFT_xFileSystemAccessRule" {
    # Test setup
    New-Item $testRoot -ItemType Directory -Force -ErrorAction 'Stop'
    $testGroup = "xFSAR_Test"
    # create an empty local group if it doesn't already exist, 
    # which we will be assigning permissions to a temp folder to in these tests.

    $foundGroup = Get-LocalGroup -Name $testGroup -ErrorAction SilentlyContinue
    if (-not $foundGroup) 
    {
        New-LocalGroup -Description "Group for MSFT_xFileSystemAccessRule tests" -Name $testGroup -ErrorAction 'Stop'
    }

    try 
    {
    
        # NOTE! Intentionally not using It blocks because these tests require being run serially, and pester no longer guarantees code outside + it blocks run sequentially.
        # Yes this could be cleaner, but I only have so much time. I feel like the test coverage is now much better than before given 
        # that the old mock-based tests didn't accurately test the code...

        Set-TargetResource -Verbose -Path "$testRoot" -Identity $testGroup -Rights @() -Ensure Absent

        # Shouldn't throw when run twice, not necessary for DSC but just verifying my test setup is safe
        Set-TargetResource -Verbose -Path "$testRoot" -Identity $testGroup -Rights @() -Ensure Absent

        $expected = $true 
        Write-Verbose -Verbose "It returns $expected when permission for nothing absent should succeed as nothing should be present currently" 
        $result = Test-TargetResource -Verbose -Path "$testRoot" -Identity $testGroup -Rights @() -Ensure Absent
        $result | Should -Be $expected
    

        $expected = $false 
        Write-Verbose -Verbose "It returns $expected when permissions should have been removed" 
        $result = Test-TargetResource -Verbose -Path "$testRoot" -Identity $testGroup -Rights @("Write") -Ensure Present
        $result | Should -Be $expected
    

        $expected = $false 
        Write-Verbose -Verbose "It returns $expected when permissions should have been removed" 
        $result = Test-TargetResource -Verbose -Path "$testRoot" -Identity $testGroup -Rights @("Write", "Read") -Ensure Present
        $result | Should -Be $expected
    
        $expected = $true 
        Write-Verbose -Verbose "It returns $expected when permissions should have been removed" 
        $result = Test-TargetResource -Verbose -Path "$testRoot" -Identity $testGroup -Rights @("Write", "Read") -Ensure Absent
        $result | Should -Be $expected
    

        $expected = $true 
        Write-Verbose -Verbose "It returns $expected when permissions should have been removed" 
        $result = Test-TargetResource -Verbose -Path "$testRoot" -Identity $testGroup -Rights @() -Ensure Absent
        $result | Should -Be $expected

        $expected = $true 
        Write-Verbose -Verbose "It returns $expected when permissions should have been removed" 
        $result = Test-TargetResource -Verbose -Path "$testRoot" -Identity $testGroup -Rights @("Read") -Ensure Absent
        $result | Should -Be $expected
    

        Set-TargetResource -Verbose -Path "$testRoot" -Identity $testGroup -Rights @("Write", "Read", "ExecuteFile") -Ensure Present

        $expected = $true 
        Write-Verbose -Verbose "It returns $expected when permission for write should be added" 
        $result = Test-TargetResource -Verbose -Path "$testRoot" -Identity $testGroup -Rights @("Write") -Ensure Present
        $result | Should -Be $expected
    

        $expected = $true 
        Write-Verbose -Verbose "It returns $expected when permission for read should be added" 
        $result = Test-TargetResource -Verbose -Path "$testRoot" -Identity $testGroup -Rights @("Read") -Ensure Present
        $result | Should -Be $expected
    

        $expected = $true 
        Write-Verbose -Verbose "It returns $expected when permission for ReadAndExecute should be added and supported via Flags" 
        $result = Test-TargetResource -Verbose -Path "$testRoot" -Identity $testGroup -Rights @("ReadAndExecute") -Ensure Present
        $result | Should -Be $expected
    


        $expected = $false 
        Write-Verbose -Verbose "It returns $expected when permission for FullControl should NOT exist yet" 
        $result = Test-TargetResource -Verbose -Path "$testRoot" -Identity $testGroup -Rights @("FullControl") -Ensure Present
        $result | Should -Be $expected
    

        $expected = $true 
        Write-Verbose -Verbose "It returns $expected when permission for FullControl should NOT be considered to be on the object for the absent so test should pass" 
        $result = Test-TargetResource -Verbose -Path "$testRoot" -Identity $testGroup -Rights @("FullControl") -Ensure Absent
        $result | Should -Be $expected
    

        Set-TargetResource -Verbose -Path "$testRoot" -Identity $testGroup -Rights @("FullControl") -Ensure Present


        $expected = $true 
        Write-Verbose -Verbose "It returns $expected when permission for FullControl should be added now" 
        $result = Test-TargetResource -Verbose -Path "$testRoot" -Identity $testGroup -Rights @("FullControl") -Ensure Present
        $result | Should -Be $expected
    


        $expected = $false 
        Write-Verbose -Verbose "It returns $expected when permission for FullControl absent should fail" 
        $result = Test-TargetResource -Verbose -Path "$testRoot" -Identity $testGroup -Rights @("FullControl") -Ensure Absent
        $result | Should -Be $expected
    


        $expected = $false 
        Write-Verbose -Verbose "It returns $expected when permission for Modify absent should fail as it is encompassed in FullControl" 
        $result = Test-TargetResource -Verbose -Path "$testRoot" -Identity $testGroup -Rights @("Modify") -Ensure Absent
        $result | Should -Be $expected
    



        $expected = $true 
        Write-Verbose -Verbose "It returns $expected when permission for Modify true should succeed as it is encompassed in FullControl" 
        $result = Test-TargetResource -Verbose -Path "$testRoot" -Identity $testGroup -Rights @("Modify") -Ensure Present
        $result | Should -Be $expected
    


        $expected = $false 
        Write-Verbose -Verbose "It returns $expected when permission for Read absent should fail as it is encompassed in FullControl" 
        $result = Test-TargetResource -Verbose -Path "$testRoot" -Identity $testGroup -Rights @("Read") -Ensure Absent
        $result | Should -Be $expected
    

        $expected = $false 
        Write-Verbose -Verbose "It returns $expected when permission for Read and Write absent should fail as both is encompassed in FullControl" 
        $result = Test-TargetResource -Verbose -Path "$testRoot" -Identity $testGroup -Rights @("Read", "Write") -Ensure Absent
        $result | Should -Be $expected
    

        $expected = $true 
        Write-Verbose -Verbose "It returns $expected when permission for Read and Write present should succeed as both are encompassed in FullControl" 
        $result = Test-TargetResource -Verbose -Path "$testRoot" -Identity $testGroup -Rights @("Read", "Write") -Ensure Present
        $result | Should -Be $expected
    



        $expected = $true 
        Write-Verbose -Verbose "It returns $expected when permission for Read and Write present should succeed as both is encompassed in FullControl" 
        $result = Test-TargetResource -Verbose -Path "$testRoot" -Identity $testGroup -Rights @("Read", "Write") -Ensure Present
        $result | Should -Be $expected
    


        $expected = $false 
        Write-Verbose -Verbose "It returns $expected when permission for Read and Write absent should fail as both is encompassed in FullControl" 
        $result = Test-TargetResource -Verbose -Path "$testRoot" -Identity $testGroup -Rights @("Read", "Write") -Ensure Absent
        $result | Should -Be $expected
    
        Set-TargetResource -Verbose -Path "$testRoot" -Identity $testGroup -Rights @() -Ensure Absent

        Set-TargetResource -Verbose -Path "$testRoot" -Identity $testGroup -Rights @("Read", "Write") -Ensure Present



        $expected = $false 
        Write-Verbose -Verbose "It returns $expected when permission for nothing absent should fail as there are permissions currently" 
        $result = Test-TargetResource -Verbose -Path "$testRoot" -Identity $testGroup -Rights @() -Ensure Absent
        $result | Should -Be $expected
    


        $expected = $false 
        Write-Verbose -Verbose "It returns $expected when permission for Read and FullControl absent should fail as Read is present currently" 
        $result = Test-TargetResource -Verbose -Path "$testRoot" -Identity $testGroup -Rights @("Read", "FullControl") -Ensure Absent
        $result | Should -Be $expected
    


        $expected = $false 
        Write-Verbose -Verbose "It returns $expected when permission for Read and FullControl absent should fail as Read is present currently" 
        $result = Test-TargetResource -Verbose -Path "$testRoot" -Identity $testGroup -Rights @() -Ensure Absent
        $result | Should -Be $expected
    



        $expected = $true 
        Write-Verbose -Verbose "It returns $expected when permission for unspecified absent on something with no ACLs should succeed" 
        $result = Test-TargetResource -Verbose -Path "$testRoot" -Identity "fake" -Rights @() -Ensure Absent
        $result | Should -Be $expected
    


        $expected = $true 
        Write-Verbose -Verbose "It returns $expected when permission for unspecified absent on something with no ACLs should succeed" 
        $result = Test-TargetResource -Verbose -Path "$testRoot" -Identity "Administrators" -Rights @() -Ensure Absent
        $result | Should -Be $expected
    


        Write-Verbose -Verbose "It returns $expected when permission for unspecified absent on path that doesn't exist should throw error" 
        $errFound = $null
        try 
        {
            $result = Test-TargetResource -Verbose -Path "$TestDrive\FakeMissingFolder" -Identity $testGroup -Rights @() -Ensure Absent -ErrorAction 'Stop'
        }
        catch { $errFound = $_ }
        if (-not $errFound) { throw "Should have had an error" }




        $expected = $false 
        Write-Verbose -Verbose "It returns $expected when permission for unspecified present on something that doesn't exist should not pass" 
        $result = Test-TargetResource -Verbose -Path "$testRoot" -Identity "fake" -Rights @("Read") -Ensure Present
        $result | Should -Be $expected
    



        Set-TargetResource -Verbose -Path "$testRoot" -Identity $testGroup -Rights @() -Ensure Absent

        Set-TargetResource -Verbose -Path "$testRoot" -Identity $testGroup -Rights @("Modify") -Ensure Present


        $expected = $true 
        Write-Verbose -Verbose "It returns $expected when permission for Read and Write present should succeed as both is encompassed in Modify" 
        $result = Test-TargetResource -Verbose -Path "$testRoot" -Identity $testGroup -Rights @("Read", "Write") -Ensure Present
        $result | Should -Be $expected
    }
    finally
    {
        # clean up
    
        Set-TargetResource -Verbose -Path "$testRoot" -Identity $testGroup -Rights @() -Ensure Absent
    }
}
