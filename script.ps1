$downloadUrl = "https://github.com/TimeCrunch101/file-sizer/releases/download/v0.1.0/anp_dir_audit.exe"
$localPath   = "C:\Users\Public\anp_dir_audit.exe"

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

function Get-File {
    param (
        [Parameter(Mandatory)][string]$Url,
        [Parameter(Mandatory)][string]$DestinationPath,
        [int]$MaxRetries = 3,
        [int]$RetryDelaySeconds = 5,
        [string]$ExpectedSha256 = $null  # optional, e.g. "ABCD...": if provided will validate
    )

    $attempt = 0
    while ($true) {
        $attempt++
        try {
            Write-Verbose "Downloading $Url to $DestinationPath (attempt $attempt)"
            # Ensure target directory exists
            $destDir = Split-Path $DestinationPath -Parent
            if (-not (Test-Path $destDir)) {
                New-Item -ItemType Directory -Path $destDir -Force | Out-Null
            }

            # Remove partial file if exists from previous failed attempt
            if (Test-Path $DestinationPath) { Remove-Item $DestinationPath -Force }

            Invoke-WebRequest -Uri $Url -OutFile $DestinationPath -UseBasicParsing -ErrorAction Stop

            if ($ExpectedSha256) {
                $actualHash = Get-FileHash -Path $DestinationPath -Algorithm SHA256
                if ($actualHash.Hash -ne $ExpectedSha256.ToUpper()) {
                    throw "Checksum mismatch. Expected $ExpectedSha256 but got $($actualHash.Hash)"
                }
            }

            Write-Verbose "Download succeeded."
            return $true
        } catch {
            Write-Warning "Download attempt $attempt failed: $_"
            if ($attempt -ge $MaxRetries) {
                throw "Failed to download $Url after $MaxRetries attempts. Last error: $_"
            }
            Start-Sleep -Seconds $RetryDelaySeconds
        }
    }
}

function Get-DirAuditSummary {
    param (
        [string]$ExePath,
        [string[]]$Arguments
    )

    # Run and capture all output (stdout+stderr)
    $raw = & $ExePath @Arguments 2>&1

    # Combine into one string for regex matching
    $text = $raw -join "`n"

    # Extract file count
    $fileCount = if ($text -match 'Total file count:\s*(\d+)') { [int]$Matches[1] } else { $null }

    # Extract folder count
    $folderCount = if ($text -match 'Total folder count:\s*(\d+)') { [int]$Matches[1] } else { $null }

    # Extract longest path length
    $longestLen = if ($text -match 'Longest file path \((\d+) chars\):') { [int]$Matches[1] } else { $null }

    # Extract longest path (next non-empty line after that header)
    $longestPath = $null
    $lines = $raw
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match 'Longest file path') {
            for ($j = $i + 1; $j -lt $lines.Count; $j++) {
                $candidate = $lines[$j].Trim()
                if ($candidate) {
                    $longestPath = $candidate
                    break
                }
            }
            break
        }
    }

    return [PSCustomObject]@{
        FileCount         = $fileCount
        FolderCount       = $folderCount
        LongestPathLength = $longestLen
        LongestPath       = $longestPath
        RawOutput         = $raw
    }
}

function Remove-MyExe {
    $maxDelAttempts = 5
    $delaySeconds = 1
    for ($i = 1; $i -le $maxDelAttempts; $i++) {
        try {
            if (Test-Path $localPath) {
                Remove-Item $localPath -Force -ErrorAction Stop
                Write-Verbose "Deleted $localPath"
            }
            break
        } catch {
            if ($i -eq $maxDelAttempts) {
                Write-Warning "Failed to delete $localPath after $maxDelAttempts attempts: $_"
            } else {
                Start-Sleep -Seconds $delaySeconds
            }
        }
    }
}

# If you have expected SHA256, set it; otherwise omit that parameter.
$expectedSha256 = "b3e69e0632cf5d608d4d4cbf7ea49ca6d70ae0e8d9ded2b31e054e2c19d92961"
Get-File -Url $downloadUrl -DestinationPath $localPath -MaxRetries 5 -RetryDelaySeconds 3 -ExpectedSha256 $expectedSha256

# At this point the file is fully downloaded and (if provided) checksum-validated.
# You can safely use it:
Write-Output "File is ready at $localPath"

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

    $exeArgs = @($share.Path)

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

    # Get Share Details
    $scanShare = Get-DirAuditSummary -ExePath $localPath -Arguments $exeArgs

    $scanDetails = [PSCustomObject]@{
        file_count = $scanShare.FileCount
        folder_count = $scanShare.FolderCount
        longest_path_count = $scanShare.LongestPathLength
        longest_path = if ($scanShare.LongestPath -eq "Top 0 largest files:") { "" } else { $scanShare.LongestPath }

    }

    # Build combined object
    $combinedList += [PSCustomObject]@{
        share_name        = $share.Name
        folder_path       = $share.Path
        unc_path          = "\\$($env:COMPUTERNAME)\$($share.Name)"
        ntfs_permissions  = $ntfsPermissions
        share_permissions = $sharePermissions
        scan_details      = $scanDetails
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
Remove-MyExe