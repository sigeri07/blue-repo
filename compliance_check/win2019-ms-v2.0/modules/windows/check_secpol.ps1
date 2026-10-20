# SID to group mapping
$sidToGroupMap = @{
    "*S-1-5-32-544" = "Administrators"
    "*S-1-5-32-548" = "Account Operators"
    "*S-1-5-11"     = "Authenticated Users"
    "*S-1-1-0"      = "Everyone"
    "*S-1-5-32-545" = "Users"
    "*S-1-5-32-551" = "Backup Operators"
    "*S-1-5-19"     = "Local Service"
    "*S-1-5-20"     = "Network Service"
    "*S-1-5-6"      = "Service"
    "*S-1-5-32-554" = "Builtin Administrators group"
    "*S-1-5-9"      = "Enterprise Domain Controllers group"
    "*S-1-5-32-549" = "Server Operators"
    "*S-1-5-32-550" = "Print Operators"
    "*S-1-5-32-555" = "Remote Desktop Users"
    "*S-1-5-32-546" = "Guests"
    "*S-1-5-32-568" = "IIS_IUSRS"
    "*S-1-5-83-0"   = "NT VIRTUAL MACHINE\Virtual Machines"
}

# Returns the lines of the exported secedit policy.
# Uses -policyFile when supplied, otherwise falls back to the $accessPolicy variable of the caller.
function Get-PolicyLines {
    param([string]$policyFile)

    if ($policyFile -and (Test-Path $policyFile)) {
        return @(Get-Content $policyFile)
    }
    return @($accessPolicy)
}

# Builds a regex that matches "<Key> = value" at the start of a line or after a registry path
# (e.g. MACHINE\...\AddPrinterDrivers=4,1). A trailing "=" in the key is tolerated.
function Get-PolicyKeyRegex {
    param([string]$PolicyKey)

    $key = $PolicyKey.Trim().TrimEnd('=').Trim()
    return '(^|[\\\s])' + [regex]::Escape($key) + '\s*='
}

function Get-PrivilegeSIDs {
    param(
        [string]$PrivilegeName,
        [hashtable]$sidToGroupMap,
        [string]$policyFile
    )

    if (-not $sidToGroupMap) { $sidToGroupMap = $script:sidToGroupMap }

    $lines   = Get-PolicyLines -policyFile $policyFile
    $pattern = Get-PolicyKeyRegex -PolicyKey $PrivilegeName
    $matched = @($lines | Select-String -Pattern $pattern)

    # secedit omits privileges that are assigned to nobody
    if ($matched.Count -eq 0) {
        return "No One"
    }

    $result = $matched | ForEach-Object {
        $value = ($_.Line -split '=', 2)[1].Trim()

        if ($value -eq "") {
            "No One"
        }
        else {
            # Split the value by commas and trim each SID
            $sids = $value -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ }
            # Map each SID to its group name if available, otherwise try to resolve it, otherwise keep the SID
            $mappedSIDs = $sids | ForEach-Object {
                $sid = $_
                if ($sidToGroupMap.ContainsKey($sid)) {
                    $sidToGroupMap[$sid]
                }
                elseif ($sid -match '^\*?S-1-') {
                    try {
                        (New-Object System.Security.Principal.SecurityIdentifier($sid.TrimStart('*'))).Translate([System.Security.Principal.NTAccount]).Value
                    }
                    catch {
                        $sid
                    }
                }
                else {
                    $sid
                }
            }
            # Sort the mapped SIDs alphabetically and join them without a trailing comma
            ($mappedSIDs | Sort-Object) -join ", "
        }
    }

    return $result
}

function Get-Policy {
    param (
        [string]$policyFile,
        [string]$PolicyKey  # The policy key to retrieve (e.g., MinimumPasswordLength, LockoutBadCount)
    )

    $lines        = Get-PolicyLines -policyFile $policyFile
    $selectedLine = @($lines | Select-String -Pattern (Get-PolicyKeyRegex -PolicyKey $PolicyKey))

    # If nothing is found, return the proper default value based on the PolicyKey
    if ($selectedLine.Count -eq 0) {
        if ($PolicyKey -eq "SeLockMemoryPrivilege") {
            return "No One"
        } else {
            return "Not Defined"
        }
    }

    # Process the value(s) if the pattern is found
    $policyValue = $selectedLine | ForEach-Object {
        # Split the line on the first '=' and trim the value
        $value = ($_.Line -split '=', 2)[1].Trim()
        if ([string]::IsNullOrWhiteSpace($value)) {
            if ($PolicyKey -eq "SeLockMemoryPrivilege") {
                "No One"
            } else {
                "Not Defined"
            }
        } else {
            $value
        }
    } | Select-Object -Unique  # Ensure only unique values are returned

    return $policyValue
}

function Get-Policy-Status {
    param (
        [string]$policyFile,
        [string]$PolicyKey  # The policy key to retrieve (e.g., PasswordComplexity, EnableGuestAccount)
    )

    $lines        = Get-PolicyLines -policyFile $policyFile
    $selectedLine = @($lines | Select-String -Pattern (Get-PolicyKeyRegex -PolicyKey $PolicyKey))

    # Check if the pattern was found
    if ($selectedLine.Count -eq 0) {
        return "Not Defined"
    }

    $policyValue = $selectedLine | ForEach-Object {
        $value = ($_.Line -split '=', 2)[1].Trim()
        if ([string]::IsNullOrEmpty($value)) {
            "Not Defined"
        } elseif ($value -eq "1" -or $value -eq "4,1") {
            "Enabled"
        } else {
            "Disabled"
        }
    } | Select-Object -Unique

    return $policyValue
}
