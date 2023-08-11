param (
    [Parameter(Mandatory=$true)][string]$name, # Name of the attestation provider
    [Parameter(Mandatory=$true)][string]$rg, # Name of the resource group
    [switch]$authenticationEnabled=$false # Set to True to enable tpmAttestationAuthentication
    )

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# Ensure AzAccount exists
$context = & Get-AzContext
if ($context -eq $null) {
    Write-Error "Please sign in to Azure using Connect-AzAccount" # e.g. Connect-AzAccount -Subscription edbd373b-0b95-4261-ae11-87aa362d8db5
    Exit 2
}

# Capture GET properties
$response = & Get-AzAttestationProvider -Name $name -ResourceGroupName $rg
$id = $response.Id
$url = 'https://management.azure.com' + $id + '?api-version=2021-06-01'

# Get token
$token = (Get-AzAccessToken).Token

# Get Attestation provider
$headers = @{
    Authorization="Bearer $token"
}
$out = & Invoke-RestMethod -Method 'Get' -Uri $url -Headers $headers -ContentType 'application/json'

$authEnabled = "Enabled"
if (!$authenticationEnabled) {
    $authEnabled = "Disabled"
}

# Modify response
$type = $out.Type
$properties = $out.Properties
$properties | Add-Member NoteProperty "tpmAttestationAuthentication" $authEnabled -Force

$headers = @{
    Authorization="Bearer $token"
    CommandName="Update-AzAttestationProvider"
    FullCommandName="Update-AzAttestationProvider_UpdateExpanded"
    ParameterSetName="__AllParameterSets"
}
$body = @{
    "id" = $id
    "name" = $name
    "type" = $type
    "properties" = $properties
}

# Update attestation provider
$out = & Invoke-WebRequest -Method 'PATCH' -Uri $url -Headers $headers -Body ($body | ConvertTo-Json -Depth 4 -Compress) -ContentType 'application/json'
Write-Output $out.Content