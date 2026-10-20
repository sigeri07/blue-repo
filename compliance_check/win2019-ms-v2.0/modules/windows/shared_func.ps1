# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

# Serialises the piped objects as a JSON *array* (also for 0 or 1 items) and returns it Base64 encoded.
# ConvertTo-Json alone emits a plain object for a single item and "null" for none, which breaks report-win.py.
function ConvertTo-Base64Json {
    param (
        [Parameter(ValueFromPipeline = $true)]
        $InputObject,
        [int]$Depth = 3
    )
    begin   { $items = New-Object System.Collections.Generic.List[object] }
    process { if ($null -ne $InputObject) { $items.Add($InputObject) } }
    end {
        if ($items.Count -eq 0) {
            $json = "[]"
        } else {
            $json = ConvertTo-Json -InputObject $items.ToArray() -Depth $Depth
        }
        [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json))
    }
}

# Converts a value to text that is safe to place inside an XML element
# (arrays are joined with a space, illegal XML characters removed, &, <, > escaped).
function ConvertTo-XmlText {
    param($Value)

    if ($null -eq $Value) { return "" }
    if ($Value -is [System.Array]) {
        $text = ($Value | ForEach-Object { "$_" }) -join " "
    } else {
        $text = "$Value"
    }
    $text = [regex]::Replace($text, '[^\x09\x0A\x0D\x20-\uD7FF\uE000-\uFFFD]', '')
    return [System.Security.SecurityElement]::Escape($text)
}

# Reads the 'Enabled' value below HKLM\...\SCHANNEL using the .NET registry API.
# Needed because key names such as "DES 56/56" contain a forward slash, which the PowerShell
# registry provider treats as a path separator (so Test-Path / Get-ItemProperty never find the key).
function Get-SchannelEnabledValue {
    param([string]$SubKey)   # relative to SCHANNEL, e.g. 'Ciphers\DES 56/56'

    $base = 'SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL'
    $key  = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("$base\$SubKey")
    if ($null -eq $key) {
        return [PSCustomObject]@{ Exists = $false; Value = $null }
    }
    try {
        $value = $key.GetValue('Enabled', $null)
    } finally {
        $key.Close()
    }
    return [PSCustomObject]@{ Exists = $true; Value = $value }
}

function Check-Service {
    param (
        [string]$serviceName
    )

    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue

    if ($null -eq $service) {
        return "Not Installed"
    } else {
        return $service.StartMode
    }
}

function Check-TrendMicro-Services {
    $services = @{
        "Trend Micro Web Service Communicator" = "Trend Micro Web Service Communicator"
        "Trend Micro Solution Platform" = "Amsp"
        "Trend Micro Endpoint Basecamp" = "Trend Micro Endpoint Basecamp"
        "Trend Micro Deep Security Notifier" = "ds_notifier"
        "Trend Micro Deep Security Monitor" = "ds_monitor"
        "Trend Micro Deep Security Agent" = "ds_agent"
        "Trend Micro Cloud Endpoint Telemetry Service" = "CETASvc"
    }

    $results = @()

    foreach ($displayName in $services.Keys) {
        $serviceName = $services[$displayName]
        $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$serviceName'" -ErrorAction SilentlyContinue

        if ($null -eq $service) {
            $status = "Not Installed"
        } else {
            $status = $service.State
        }

        $results += [PSCustomObject]@{
            "Service Name"  = $displayName
            "Service Status" = $status
        }
    }

    # Format-Table emits formatting objects; Out-String turns them into plain text for the XML report
    return (($results | Format-Table -AutoSize | Out-String).Trim())
}


function Get-AllUserDetails {
    # Get all local users
    $users = @(Get-LocalUser)

    # Build a SID -> group names map once (instead of enumerating every group for every user,
    # and matching on SID instead of a regex on the name, so "Admin" no longer matches "Administrator")
    $groupsBySid = @{}
    foreach ($group in @(Get-LocalGroup)) {
        $members = Get-LocalGroupMember -Group $group.Name -ErrorAction SilentlyContinue
        foreach ($member in $members) {
            $sid = $member.SID.Value
            if (-not $groupsBySid.ContainsKey($sid)) {
                $groupsBySid[$sid] = New-Object System.Collections.Generic.List[string]
            }
            $groupsBySid[$sid].Add($group.Name)
        }
    }

    $userDetails = foreach ($user in $users) {
        $groups = @()
        if ($groupsBySid.ContainsKey($user.SID.Value)) {
            $groups = $groupsBySid[$user.SID.Value]
        }

        [PSCustomObject]@{
            User               = $user.Name
            Groups             = $groups -join ", "
            LastLogin          = $user.LastLogon
            LastPasswordChange = $user.PasswordLastSet
            Status             = $user.Enabled
        }
    }

    # Convert output to a JSON array and encode in Base64
    return ($userDetails | ConvertTo-Base64Json -Depth 2)
}
function Check-TaskScheduler {
    $taskDetails = Get-ScheduledTask | ForEach-Object {
        $taskInfo = Get-ScheduledTaskInfo -TaskName $_.TaskName -TaskPath $_.TaskPath -ErrorAction SilentlyContinue        
        $lastRunTimeStr = "N/A"
        if ($taskInfo -and $taskInfo.LastRunTime -and ($taskInfo.LastRunTime -ne [datetime]::MinValue)) {
            $lastRunTimeStr = $taskInfo.LastRunTime.ToString("yyyy-MM-dd HH:mm:ss")
        }        
        #if ($lastRunTimeStr -eq "1999-11-30 00:00:00") {
        #    return
        #}        
        $scheduleEnabled = if ($_.Triggers -and $_.Triggers.Count -gt 0) {
            $_.Triggers[0].Enabled
        } else {
            "N/A"
        }        
        $nextRunTimeStr = "N/A"
        if ($taskInfo -and $taskInfo.NextRunTime -and ($taskInfo.NextRunTime -ne [datetime]::MinValue)) {
            $nextRunTimeStr = $taskInfo.NextRunTime.ToString("yyyy-MM-dd HH:mm:ss")
        }        
        $user = $_.Principal.UserId        
        $binaryPath = if ($_.Actions -and $_.Actions.Count -gt 0) {
            "$($_.Actions[0].Execute) $($_.Actions[0].Arguments)"
        } else {
            $null
        }        
        [PSCustomObject]@{
            TaskName        = $_.TaskName
            TaskPath        = $_.TaskPath
            State           = if ($taskInfo) { $taskInfo.State } else { "Unknown" }
            LastRunTime     = $lastRunTimeStr
            NextRunTime     = $nextRunTimeStr
            User            = $user
            BinaryPath      = $binaryPath
            ScheduleEnabled = $scheduleEnabled
        }
    }
    return ($taskDetails | ConvertTo-Base64Json -Depth 3)
}

function Get-AvailableUpdates {
    try {
        # Create a Windows Update session and searcher
        $updateSession   = New-Object -ComObject Microsoft.Update.Session
        $updateSearcher  = $updateSession.CreateUpdateSearcher()

        # Search for available updates (not installed and not hidden)
        $searchResult = $updateSearcher.Search("IsInstalled=0 and IsHidden=0")

        # Build a list of available update details
        $updates = foreach ($update in $searchResult.Updates) {
            [PSCustomObject]@{
                Title          = $update.Title
                UpdateID       = $update.Identity.UpdateID
                RebootRequired = $update.RebootRequired
                KBArticleIDs   = if ($update.KBArticleIDs) { @($update.KBArticleIDs) -join ", " } else { "" }
            }
        }

        return ($updates | ConvertTo-Base64Json -Depth 3)
    }
    catch {
        Write-Warning "Error checking for available updates: $_"
        # Return an empty list so the report still contains a valid <Updates> section
        return ($null | ConvertTo-Base64Json)
    }
}

function Get-InstalledSoftware {
    # Array to store software information
    $softwareList = @()
    
    # Define registry paths for installed software
    $registryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    
    # Iterate through each registry path and retrieve software details
    foreach ($path in $registryPaths) {
        $items = Get-ItemProperty $path -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName }
        foreach ($item in $items) {
            $softwareList += [PSCustomObject]@{
                DisplayName    = $item.DisplayName
                DisplayVersion = $item.DisplayVersion
                Publisher      = $item.Publisher
                InstallDate    = $item.InstallDate
            }
        }
    }
    
    return ($softwareList | ConvertTo-Base64Json -Depth 3)
}

function Get-RunningServices {
    # Get running services using WMI for detailed properties and sort by State
    $serviceDetails = Get-WmiObject Win32_Service | ForEach-Object {
        [PSCustomObject]@{
            Name        = $_.Name
            DisplayName = $_.DisplayName
            State       = $_.State
            StartMode   = $_.StartMode
            RunAs       = $_.StartName  # The account under which the service runs
            PID         = $_.ProcessId  # The process ID of the service
        }
    } | Sort-Object -Property State
    
    return ($serviceDetails | ConvertTo-Base64Json -Depth 2)
}

function Get-ListenPort {
    # Retrieve all TCP connections in the Listen state
    $connectionDetails = Get-NetTCPConnection -State Listen | ForEach-Object {
        # Try to get the process details using the OwningProcess ID
        $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            LocalAddress = $_.LocalAddress
            LocalPort    = $_.LocalPort
            PID          = $_.OwningProcess
            ProcessName  = if ($proc) { $proc.ProcessName } else { "Unknown" }
        }
    }
    
    return ($connectionDetails | ConvertTo-Base64Json -Depth 3)
}

function Get-RunningProcesses {
    # Query Win32_Process once; a missing/denied owner no longer causes "method call on null" errors
    $cimProcesses = @{}
    foreach ($cp in @(Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue)) {
        $cimProcesses[[int]$cp.ProcessId] = $cp
    }

    $processDetails = foreach ($process in Get-Process) {
        $cp    = $cimProcesses[[int]$process.Id]
        $owner = "N/A"
        if ($cp) {
            $o = Invoke-CimMethod -InputObject $cp -MethodName GetOwner -ErrorAction SilentlyContinue
            if ($o -and $o.ReturnValue -eq 0 -and $o.User) {
                $owner = "$($o.Domain)\$($o.User)"
            }
        }

        $path = $process.Path
        if (-not $path -and $cp) { $path = $cp.ExecutablePath }

        [PSCustomObject]@{
            ProcessName = $process.ProcessName
            ProcessID   = $process.Id
            Path        = $path
            UserName    = $owner
        }
    }

    # Convert output to a JSON array and encode in Base64
    return ($processDetails | ConvertTo-Base64Json -Depth 2)
}

function check_strong_tls {
    $registryPaths = @(
        "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server",
        "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client"
    )

    $allEnabled = $true
    $messages = @()

    foreach ($path in $registryPaths) {
        if (Test-Path $path) {
            $enabledValue = Get-ItemProperty -Path $path -Name "Enabled" -ErrorAction SilentlyContinue

            if ($enabledValue) {
                # Any non-zero value counts as enabled (IIS Crypto writes 0xFFFFFFFF, which reads back as -1)
                if ($enabledValue.Enabled -ne 0) {
                    $messages += "$path is Enabled."
                } else {
                    $allEnabled = $false
                    $messages += "$path is Disabled (Enabled = 0)."
                }
            } else {
                $allEnabled = $false
                $messages += "$path does not configured."
            }
        } else {
            $allEnabled = $false
            $messages += "$path does not exist."
        }
    }

    if ($allEnabled) {
        return "TLS 1.2 protocol is enabled"
    } else {
        return ($messages -join "; ")
    }
}
function check_weak_des {
    # "DES 56/56" contains a '/', so it must be read through the .NET registry API (see Get-SchannelEnabledValue)
    $subKeys = @(
        "Ciphers\DES 56/56"
    )

    # Flag to track if all ciphers are disabled
    $allDisabled = $true
    $messages = @()

    foreach ($subKey in $subKeys) {
        $path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\$subKey"
        $info = Get-SchannelEnabledValue -SubKey $subKey

        if (-not $info.Exists) {
            # No explicit configuration: not guaranteed to be disabled
            $allDisabled = $false
            $messages += "$path does not exist. You may need to create the path and set the 'Enabled' value to 0."
        } elseif ($null -eq $info.Value) {
            $allDisabled = $false
            $messages += "$path does not have the 'Enabled' value. You may need to add the 'Enabled' value and set it to 0."
        } elseif ($info.Value -eq 0) {
            $messages += "$path is already disabled."
        } else {
            $allDisabled = $false
            $messages += "$path is enabled. You need to change the value to 0 to disable it."
        }
    }

    # Final output based on whether all ciphers are disabled or not
    if ($allDisabled) {
        return "DES encryption is disabled"
    } else {
        return ($messages -join "; ")
    }
}

function check_weak_ssl {
    $registryPaths = @(
        "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server",
        "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client",
        "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server",
        "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client"
	)
    # Flag to track if all protocols are disabled
    $allDisabled = $true
    $messages = @()

    # Iterate through each registry path
    foreach ($path in $registryPaths) {
        if (Test-Path $path) {
            # Try to get the 'Enabled' value
            $enabledValue = Get-ItemProperty -Path $path -Name "Enabled" -ErrorAction SilentlyContinue
            
            if ($enabledValue) {
                # Check if the 'Enabled' value is 0 (disabled)
                if ($enabledValue.Enabled -eq 0) {
                    $messages += "$path is already disabled."
                } else {
                    # If 'Enabled' is not 0, it's considered enabled
                    $allDisabled = $false
                    $messages += "$path is enabled. You need to change the value to 0 to disable it."
                }
            } else {
                # If 'Enabled' doesn't exist, the protocol is not explicitly disabled (reported as non-compliant)
                $allDisabled = $false
                $messages += "$path does not have the 'Enabled' value. You may need to add the 'Enabled' value and set it to 0."
            }
        } else {
            # If the registry path does not exist, the protocol is not explicitly disabled (reported as non-compliant)
            $allDisabled = $false
            $messages += "$path does not exist. You may need to create the path and set the 'Enabled' value to 0."
        }
    }

    # Final output based on whether all protocols are disabled or not
    if ($allDisabled) {
        return "Both SSLv2 and SSLv3 protocol are disabled"
    } else {
        # Return all messages related to the current state
        return ($messages -join "; ")
    }
}

function check_weak_tls {
    $registryPaths = @(
        "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server",
        "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client",
        "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server",
        "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client"
    )

    # Flag to track if all protocols are disabled
    $allDisabled = $true
    $messages = @()

    # Iterate through each registry path
    foreach ($path in $registryPaths) {
        if (Test-Path $path) {
            # Try to get the 'Enabled' value
            $enabledValue = Get-ItemProperty -Path $path -Name "Enabled" -ErrorAction SilentlyContinue
            
            if ($enabledValue) {
                # Check if the 'Enabled' value is 0 (disabled)
                if ($enabledValue.Enabled -eq 0) {
                    $messages += "$path is already disabled."
                } else {
                    # If 'Enabled' is not 0, it's considered enabled
                    $allDisabled = $false
                    $messages += "$path is enabled. You need to change the value to 0 to disable it."
                }
            } else {
                # If 'Enabled' doesn't exist, the protocol is not explicitly disabled (reported as non-compliant)
                $allDisabled = $false
                $messages += "$path does not have the 'Enabled' value. You may need to add the 'Enabled' value and set it to 0."
            }
        } else {
            # If the registry path does not exist, the protocol is not explicitly disabled (reported as non-compliant)
            $allDisabled = $false
            $messages += "$path does not exist. You may need to create the path and set the 'Enabled' value to 0."
        }
    }

    # Final output based on whether all protocols are disabled or not
    if ($allDisabled) {
        return "Both TLS 1.0 and TLS 1.1 protocols are disabled"
    } else {
        # Return all messages related to the current state
        return ($messages -join "; ")
    }
}

function Get-RemotelyAccessibleRegistryPaths {
    $ExpectedRegistryKeys = @(
        "System\CurrentControlSet\Control\Print\Printers",
        "System\CurrentControlSet\Services\Eventlog",
        "Software\Microsoft\OLAP Server",
        "Software\Microsoft\Windows NT\CurrentVersion\Print",
        "Software\Microsoft\Windows NT\CurrentVersion\Windows",
        "System\CurrentControlSet\Control\ContentIndex",
        "System\CurrentControlSet\Control\Terminal Server",
        "System\CurrentControlSet\Control\Terminal Server\UserConfig",
        "System\CurrentControlSet\Control\Terminal Server\DefaultUserConfiguration",
        "Software\Microsoft\Windows NT\CurrentVersion\Perflib",
        "System\CurrentControlSet\Services\SysmonLog"
    )

    $RegKey = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg\AllowedPaths"

    $RemotelyAccessibleRegistryPaths = if (Test-Path -Path $RegKey) {
        # Get the Machine property from the registry key, split by null character, clean up spaces
        (Get-ItemProperty -Path $RegKey -Name "Machine" -ErrorAction SilentlyContinue | 
        ForEach-Object { $_.Machine -split '\0' }).Replace(" ","").Trim()
    } else {
        $null
    }

    # Check which of the expected registry paths are in the allowed remote paths
    $AccessiblePaths = @()
    if ($RemotelyAccessibleRegistryPaths) {
        foreach ($ExpectedPath in $ExpectedRegistryKeys) {
            if ($RemotelyAccessibleRegistryPaths -contains $ExpectedPath) {
                $AccessiblePaths += $ExpectedPath
            }
        }
    }

    return $AccessiblePaths
}


function check_notconnecteduser {
    $regKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $regValueName = "NoConnectedUser"

    # Initialize the result variable
    $NoConnectedUser = "Not Defined"

    if (Test-Path $regKeyPath) {
        $value = Get-ItemProperty -Path $regKeyPath -Name $regValueName -ErrorAction SilentlyContinue

        if ($value) {
            # Switch statement to map the value to a human-readable result
            switch ($value.NoConnectedUser) {
                0 { $NoConnectedUser = "This policy is disabled" }
                1 { $NoConnectedUser = "Users can't add Microsoft accounts" }
                3 { $NoConnectedUser = "Users can't add or log on with Microsoft accounts" }
                default { $NoConnectedUser = "Unknown or Not Defined" }
            }
        } else {
            $NoConnectedUser = "Not Defined"
        }
    } else {
        $NoConnectedUser = "Not Defined"
    }

    # Return the result
    return $NoConnectedUser
}
# Define the function to check the ScheduledInstallDay registry value
function Get-ScheduledInstallDayStatus {
    param (
        [string]$RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU",
        [string]$RegistryName = "ScheduledInstallDay"
    )

    # Check if the registry key exists before accessing the property
    $scheduledInstallDayKey = Get-ItemProperty -Path $RegistryPath -Name $RegistryName -ErrorAction SilentlyContinue

    # If the key exists, evaluate the value, otherwise return "Not Configured"
    if ($null -ne $scheduledInstallDayKey) {
        $scheduledInstallDay = $scheduledInstallDayKey.ScheduledInstallDay
        if ($scheduledInstallDay -eq 0) {
            return "0 - Every day"
        } elseif ($scheduledInstallDay -eq 1) {
            return "Disabled"
        } else {
            return "Not Configured"
        }
    } else {
        return "Not Configured"
    }
}

function AllocateDASD {
    $regKeyPath = "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $regValueName = "AllocateDASD"

    # Initialize the result variable
    $AllocateDASD = "Not Defined"

    if (Test-Path $regKeyPath) {
        $value = Get-ItemProperty -Path $regKeyPath -Name $regValueName -ErrorAction SilentlyContinue

        if ($value) {
            # Check the value of AllocateDASD and set the appropriate message
            if ($value.$regValueName -eq 0) {
                $AllocateDASD = "Administrator"
            } else {
                $AllocateDASD = "Not Defined"
            }
        } else {
            $AllocateDASD = "Not Defined"
        }
    } else {
        $AllocateDASD = "Not Defined"
    }

    # Return the result
    return $AllocateDASD
}

# Function to remove null characters from the string
function Remove-NullCharacters {
    param (
        [string]$inputString
    )
    return $inputString -replace [char]0, ''
}

# Function to get registry value and process it
function Get-RegistryValue {
    param (
        [string]$regKeyPath,
        [string]$regValueName
    )
    
    if (Test-Path $regKeyPath) {
        $value = Get-ItemProperty -Path $regKeyPath -Name $regValueName -ErrorAction SilentlyContinue
        
        if ($value) {
            $result = $value.$regValueName
            # If the value is for LegalNoticeText, remove null characters
            if ($regValueName -eq "LegalNoticeText") {
                $result = Remove-NullCharacters -inputString $result
            }
            return $result
        } else {
            return "Not Defined"
        }
    } else {
        return "Registry key not found"
    }
}

function Get-SupportedEncryptionTypes {
    param (
        [string]$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters",
        [string]$regValue = "SupportedEncryptionTypes"
    )

    # Check if the registry path exists
    if (Test-Path $regPath) {
        # Get the registry value for SupportedEncryptionTypes
        $value = Get-ItemProperty -Path $regPath -Name $regValue -ErrorAction SilentlyContinue

        # Check if the value exists and is not null
        if ($value) {
            if ($value.$regValue -eq 2147483640) {
                $SupportedEncryptionTypes = "AES128_HMAC_SHA1, AES256_HMAC_SHA1, Future encryption types"
            } else {
                $SupportedEncryptionTypes = "Not Defined"
            }
        } else {
            $SupportedEncryptionTypes = "Not Defined"
        }
    } else {
        $SupportedEncryptionTypes = "Not Defined"
    }

    # Return the result
    return $SupportedEncryptionTypes
}

function Get-NetworkLANManagerSetting {
    param (
        [string]$RegKey = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa",
        [string]$RegValueName = "LmCompatibilityLevel"
    )

    # Define a mapping for the possible values (plain "&": XML escaping is done when the report is written)
    $Mapping = @{
        0 = "Send LM & NTLM responses"
        1 = "Send LM & NTLM - Use NTLMv2 session security if negotiated"
        2 = "Send NTLM response only"
        3 = "Send NTLMv2 response only"
        4 = "Send NTLMv2 response only. Refuse LM"
        5 = "Send NTLMv2 response only. Refuse LM & NTLM"
    }

    if (-not (Test-Path -Path $RegKey)) {
        return "Registry key not found"
    }

    $CurrentValue = (Get-ItemProperty -Path $RegKey -Name $RegValueName -ErrorAction SilentlyContinue).$RegValueName

    if ($null -eq $CurrentValue) {
        return "Registry value not set"
    } elseif ($Mapping.ContainsKey([int]$CurrentValue)) {
        return $Mapping[[int]$CurrentValue]
    } else {
        return "Unknown value"
    }
}

function Get-NTLMMinSecuritySetting {
    param (
        [string]$regKeyPath,
        [string]$regValueName
    )

    # Check if the registry key exists
    if (Test-Path $regKeyPath) {
        try {
            # Get the registry value
            $value = Get-ItemProperty -Path $regKeyPath -Name $regValueName -ErrorAction Stop
            if ($value) {
                # Extract the value
                $val = $value.$regValueName
                # Determine the setting based on the decimal value
                switch ($val) {
                    537395200 { return "Require NTLMv2 session security, Require 128-bit encryption" }  # 0x20080000 = NTLMv2 session security (0x80000) + 128-bit encryption (0x20000000)
                    524288  { return "Require NTLMv2 session security, but does not require 128-bit encryption" }  # 0x00080000 = NTLMv2 session security only
                    536870912 { return "Require 128-bit encryption, but does not require NTLMv2 session security" }  # 0x20000000 = 128-bit encryption only
                    default     { return "Setting not configured to require NTLMv2 session security and 128-bit encryption" }
                }
            } else {
                return "Not Defined"
            }
        } catch {
            return "Error retrieving registry value: $_"
        }
    } else {
        return "Registry key not found"
    }
}

# Function to get ConsentPromptBehaviorAdmin setting
function Get-ConsentPromptBehaviorAdmin {
    param (
        [string]$regKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        [string]$regValueName = "ConsentPromptBehaviorAdmin"
    )

    # Check if the registry key exists
    if (Test-Path $regKeyPath) {
        try {
            # Get the registry value
            $value = Get-ItemProperty -Path $regKeyPath -Name $regValueName -ErrorAction SilentlyContinue

            if ($value) {
                # Determine the setting based on the registry value
                switch ($value.ConsentPromptBehaviorAdmin) {
                    0 { return "Elevate without prompting" }
                    1 { return "Prompt for credentials on the secure desktop" }
                    2 { return "Prompt for consent on the secure desktop" }
                    3 { return "Prompt for credentials" }
                    4 { return "Prompt for consent" }
                    5 { return "Prompt for consent for non-Windows binaries" }
                    default { return "Unknown or Not Defined" }
                }
            } else {
                return "Not Defined"
            }
        } catch {
            return "Error retrieving registry value: $_"
        }
    } else {
        return "Registry key not found"
    }
}

# Function to get ConsentPromptBehaviorUser setting
function Get-ConsentPromptBehaviorUser {
    param (
        [string]$regKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        [string]$regValueName = "ConsentPromptBehaviorUser"
    )

    # Check if the registry key exists
    if (Test-Path $regKeyPath) {
        try {
            # Get the registry value
            $value = Get-ItemProperty -Path $regKeyPath -Name $regValueName -ErrorAction SilentlyContinue

            if ($value) {
                # Determine the setting based on the registry value
                switch ($value.ConsentPromptBehaviorUser) {
                    0 { return "Automatically deny elevation requests" }
                    1 { return "Prompt for credentials on the secure desktop" }
                    3 { return "Prompt for credentials" }
                    default { return "Unknown or Not Defined" }
                }
            } else {
                return "Not Defined"
            }
        } catch {
            return "Error retrieving registry value: $_"
        }
    } else {
        return "Registry key not found"
    }
}
function Get-SupportDeviceAuthenticationStatus {
    # Retrieve the registry values for DevicePKInitBehavior and DevicePKInitEnabled
    $DevicePKInitBehavior = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters" -Name "DevicePKInitBehavior" -ErrorAction SilentlyContinue).DevicePKInitBehavior
    $DevicePKInitEnabled = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\kerberos\parameters" -Name "DevicePKInitEnabled" -ErrorAction SilentlyContinue).DevicePKInitEnabled

    # Check conditions and assign the SupportDeviceAuthentication status
    if ($null -eq $DevicePKInitBehavior -or $null -eq $DevicePKInitEnabled) {
        $SupportDeviceAuthentication = "Disabled or Not Configured"
    } elseif ($DevicePKInitBehavior -eq 0 -and $DevicePKInitEnabled -eq 1) {
        $SupportDeviceAuthentication = "Enabled: Automatic"
    } else {
        $SupportDeviceAuthentication = "Disabled or Not Configured"
    }

    return $SupportDeviceAuthentication
}

function Get-FWRegValue {
    param (
        [string]$regKeyPath,
        [string]$regValueName
    )
    
    try {
        $regValue = Get-ItemProperty -Path $regKeyPath -Name $regValueName -ErrorAction Stop
        switch ($regValueName) {
            "LogSuccessfulConnections" {
                if ($regValue.$regValueName -eq 1) {return "Yes"}
                elseif ($regValue.$regValueName -eq 0) {return "No"}
            }
            "LogDroppedPackets" {
                if ($regValue.$regValueName -eq 1) {return "Yes"}
                elseif ($regValue.$regValueName -eq 0) {return "No"}
            }
            "AllowLocalPolicyMerge" {
                if ($regValue.$regValueName -eq 1) {return "Yes"}
                elseif ($regValue.$regValueName -eq 0) {return "No"}
            }
            "AllowLocalIPsecPolicyMerge" {
                if ($regValue.$regValueName -eq 1) {return "Yes"}
                elseif ($regValue.$regValueName -eq 0) {return "No"}
            }
            "EnableFirewall" {
                if ($regValue.$regValueName -eq 1) {return "On (recommended)"}
                elseif ($regValue.$regValueName -eq 0) {return "Off"}
            }
            "DefaultInboundAction" {
                if ($regValue.$regValueName -eq 1) {return "Block (default)"}
                elseif ($regValue.$regValueName -eq 0) {return "Allow"}
            }
			"DefaultOutboundAction" {
                if ($regValue.$regValueName -eq 1) {return "Block (default)"}
                elseif ($regValue.$regValueName -eq 0) {return "Allow"}
            }
            "LogFilePath" {
                return $regValue.$regValueName
            }
            default {
                Write-Host "Error: Unknown registry value '$regValueName'."
                return
            }
        }
    }
    catch {
        return @("Not Defined")
    }
}

function Get-AuditPolSetting {
    param (
        [string]$subcategory
    )

    # Get the current audit policy for the specified subcategory
    $value = auditpol /get /subcategory:"$subcategory" 2>$null
    
    # Check if the subcategory value matches expected patterns
    if ($value -match "Success and Failure") {
        return "Success and Failure"
    } elseif ($value -match "Success") {
        return "Success"
    } elseif ($value -match "Failure") {
        return "Failure"
    } elseif ($value -match "No Auditing") {
        return "No Auditing"
    } else {
        return "Not Defined"
    }
}
function Get-RegistryTimeSetting {
    param (
        [string]$regKeyPath,
        [string]$regValueName,
        [int]$expectedValue,     # kept for backward compatibility, no longer used
        [string]$defaultMessage  # kept for backward compatibility, no longer used
    )

    if (-not (Test-Path $regKeyPath)) {
        return "Not Configured"
    }

    try {
        $Value = Get-ItemProperty -Path $regKeyPath -Name $regValueName -ErrorAction SilentlyContinue
        if (-not $Value) {
            return "Not Configured"
        }

        $milliseconds = [double]$Value.$regValueName
        if ($milliseconds -eq 0) {
            return "Enabled: Never"
        }

        # Convert milliseconds to minutes, using the same wording as the control file ("Enabled: 1 minute")
        $minutes = [math]::Round($milliseconds / 60000, 2)
        $unit = if ($minutes -eq 1) { "minute" } else { "minutes" }
        return "Enabled: $minutes $unit"
    } catch {
        return "Error retrieving registry value"
    }
}
