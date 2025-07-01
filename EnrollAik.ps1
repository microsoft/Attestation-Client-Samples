<#
.DESCRIPTION
This script is designed to create a TPM Attestation Identity Key (AIK) and retrieve an AIK certificate for use with the Microsoft Azure Attestation service.
.NOTES
This script must be run from an Admin window.
.PARAMETER KeyName
Name of the key to be created.
.PARAMETER AclIdentity
Changes the ACL on the key so it can be read by the user/group specified by this parameter. This can be used to configure the account under which the MAA client executes so it does not have to be run with elevated permissions.
The script can also be used to configure the ACL on a previously created key.
.PARAMETER AclIdentitySid
Changes the ACL on the key so it can be read by the SID specified by this parameter. This can be used to configure the account under which the MAA client executes so it does not have to be run with elevated permissions.
The script can also be used to configure the ACL on a previously created key.
.EXAMPLE
EnrollAik.ps1 MyOrgAik
=> Creates an AIK called "MyOrgAik" and enrolls it with Azure Certificate Services to get an associated AIK certificate.
.EXAMPLE
EnrollAik.ps1 MyOrgAik -AclIdentity TestAccount
=> Creates an AIK called "MyOrgAIK" and enrolls it with Azure Certificate Services to get an associated AIK certificate.
Additionally, grants read permission on the key to "TestAccount".
.EXAMPLE
EnrollAik.ps1 MyOrgAik -AclIdentity "NT AUTHORITY\Authenticated Users"
=> Creates an AIK called "MyOrgAIK" and enrolls it with Azure Certificate Services to get an associated AIK certificate.
Additionally, grants read permission on the key to all Authenticated users (those signed into the domain).
.EXAMPLE
EnrollAik.ps1 MyOrgAik -AclIdentitySid "S-1-5-11"
=> Creates an AIK called "MyOrgAIK" and enrolls it with Azure Certificate Services to get an associated AIK certificate.
Additionally, grants read permission on the key to all Authenticated users (those signed into the domain) using a SID.
#>

<# Copyright (c) Microsoft Corporation.  All rights reserved. #>

[CmdletBinding(DefaultParameterSetName = 'AclIdentity')]
Param(
    [Parameter(Mandatory = $true, Position = 0)][string]$KeyName,
    [Parameter(ParameterSetName = 'AclIdentity')][string]$AclIdentity,
    [Parameter(ParameterSetName = 'AclIdentitySid')][string]$AclIdentitySid
)

function PrettyPrintCapturedOutput {
    param (
        [Parameter(Mandatory = $true)]$output,
        [Parameter()][switch]$isError
    )
    if ($isError) {
        foreach ($line in $output) {
            # Write-Host instead of Write-Error since Error will print the line number and make it seem like the error comes from this function.
            Write-Host "$line`n" -ForegroundColor Red
        }
    }
    else {
        foreach ($line in $output) {
            Write-Debug "$line`n" 
        }
    }
}

Write-Host "Beginning request... (This can take up to a few minutes depending on the TPM performance)" -ForegroundColor Green
$cmdLine = "certreq.exe -enrollaik -f -machine -config ```"```" $KeyName"
Write-Debug "Create AIK and request cert: $cmdLine"
$reqOutput = Invoke-Expression -Command $cmdLine

# If the key has been previously created certreq will return NTE_EXISTS. By allowing this or S_OK, the script can also ACL keys that have been previously created.
$NTE_KEY_EXISTS = -2146893809
if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq $NTE_KEY_EXISTS) {
    PrettyPrintCapturedOutput $reqOutput
    Write-Host "Key is available." -ForegroundColor Green

    if ($AclIdentity -or $AclIdentitySid) {
        if ($AclIdentity) {
            $identity = $AclIdentity
        }
        else {
            $identity = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $AclIdentitySid
        }
           
        Write-Host "Granting read access to $identity..." -ForegroundColor Green

        # Retrieve the disk location for the key
        $cmdLine = "certutil.exe -CSP TPM -key $KeyName"
        Write-Debug "Find key location: $cmdLine"
        $utilOutput = Invoke-Expression -Command $cmdLine
        PrettyPrintCapturedOutput $utilOutput

        if ($LASTEXITCODE -eq 0) {
            $keyPath = $utilOutput[2].trim()
            if (-not($keyPath -like "$($env:ProgramData)\Microsoft\Crypto\PCPKSP\*")) {
                Write-Error "The format of CertUtil output doesn't match the expected value and might have changed."
                Write-Error "Please adjust the script accordingly to ensure the proper file is ACL'd correctly for read access."
                PrettyPrintCapturedOutput $utilOutput -isError
                return
            }

            $acl = Get-Acl -Path $keyPath
            # Set read ACE
            $fileSystemRights = "Read"
            $type = "Allow"
            # Create new rule
            $fileSystemAccessRuleArgumentList = $identity, $fileSystemRights, $type
            $fileSystemAccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList $fileSystemAccessRuleArgumentList
            # Apply new rule to object (setting same ACL multiple times has no effect, so no need to check if rule is already set)
            $acl.SetAccessRule($fileSystemAccessRule)
            Set-Acl -Path $keyPath -AclObject $acl

            $acl = Get-Acl -path $keyPath
            Write-Debug ($acl.Access | Format-List | out-string)
            Write-Host "Key is accessible by $identity now." -ForegroundColor Green
        }
        else {
            Write-Error "Unexpected return from certutil ($($LASTEXITCODE)) when searching for $KeyName. The key has *not* been ACL'd."
            PrettyPrintCapturedOutput $utilOutput -isError
        }
    }
}
else {
    # CertReq failed, print output to user
    PrettyPrintCapturedOutput $reqOutput -isError
}