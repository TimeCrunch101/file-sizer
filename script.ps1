function Get-SharePermissions {
    param (
        [string]$shareName
    )

    try {
        $shareSec = Get-WmiObject -Class Win32_LogicalShareSecuritySetting -Filter "Name='$shareName'"
        $result = @()

        $null = $shareSec.GetSecurityDescriptor().Descriptor.DACL | ForEach-Object {
            $result += [PSCustomObject]@{
                IdentityReference  = "$($_.Trustee.Domain)\$($_.Trustee.Name)"
                AccessMask         = $_.AccessMask
                AccessType         = switch ($_.AceType) {
                    0 { "Allow" }
                    1 { "Deny" }
                    default { "Unknown" }
                }
                InheritanceFlags   = $_.AceFlags
            }
        }

        return $result
    } catch {
        return @()
    }
}

# Get shared folders excluding print$, NETLOGON, and SYSVOL
$shares = Get-WmiObject -Class Win32_Share |
    Where-Object {
        $_.Type -eq 0 -and
        $_.Path -notlike '\\?\GLOBALROOT\*' -and
        $_.Name -notin @('print$', 'NETLOGON', 'SYSVOL')
    }


# Combined output
$combinedList = @()

foreach ($share in $shares) {
    # Get NTFS permissions
    try {
        $acl = Get-Acl -Path $share.Path
        $ntfsPermissions = $acl.Access | ForEach-Object {
            [PSCustomObject]@{
                IdentityReference  = $_.IdentityReference.ToString()
                FileSystemRights   = $_.FileSystemRights.ToString()
                AccessControlType  = $_.AccessControlType.ToString()
                IsInherited        = $_.IsInherited
                InheritanceFlags   = $_.InheritanceFlags.ToString()
                PropagationFlags   = $_.PropagationFlags.ToString()
            }
        }
    } catch {
        $ntfsPermissions = @()
    }

    # Get Share permissions
    $sharePermissions = Get-SharePermissions -shareName $share.Name

    # Build combined object
    $combinedList += [PSCustomObject]@{
        share_name        = $share.Name
        folder_path       = $share.Path
        unc_path          = "\\$($env:COMPUTERNAME)\$($share.Name)"
        ntfs_permissions  = $ntfsPermissions
        share_permissions = $sharePermissions
    }
}

# Wrap in root object
$payload = @{
    shares = $combinedList
} | ConvertTo-Json -Depth 5

# API endpoint
$uri = "{{CTX.webhook_endpoint.url}}"

# Headers
$headers = @{
    "Content-Type" = "application/json"
}

# POST to API
$response = Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $payload

# Output result
Write-Host "Response from API:"
$response
