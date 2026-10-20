# windows-2019-ms.ps1
# Collects the Windows Server 2019 (member server) security baseline results into dump.xml.
# Run from an elevated PowerShell prompt, then feed dump.xml to report-win.py.

# secedit, auditpol and several registry/WMI queries need administrator rights
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

# Modules are loaded relative to the script itself, so it works from any working directory.
# Output files (secedit.inf, dump.xml) are written to the directory the script is started from.
$scriptDir  = if ($PSScriptRoot) { $PSScriptRoot } else { $PWD.Path }
$currentDir = $PWD.Path
$policyFile = Join-Path $currentDir "secedit.inf"

secedit /export /cfg $policyFile /quiet
if (-not (Test-Path $policyFile)) {
    Write-Error "secedit failed to export the local security policy to $policyFile"
    exit 1
}
$accessPolicy = Get-Content $policyFile

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$hostname = $env:COMPUTERNAME
$os = (Get-CimInstance -ClassName Win32_OperatingSystem).Caption
$currentUser = $env:USERNAME
$ipAddresses = (Get-NetIPAddress | Where-Object {$_.AddressFamily -eq "IPv4" -and $_.InterfaceAlias -notlike "*Loopback*"}).IPAddress -join ", "

$computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
$domain = ""
$ou = ""
$workgroupName = ""

if ($computerSystem.PartOfDomain) {
    $domain = $computerSystem.Domain
    try {
        if (Get-Command Get-ADComputer -ErrorAction SilentlyContinue) {
            $dn = (Get-ADComputer $computerSystem.Name -Properties DistinguishedName -ErrorAction Stop).DistinguishedName
        } else {
            # RSAT / ActiveDirectory module not installed: fall back to an ADSI lookup
            $searcher = [adsisearcher]"(&(objectCategory=computer)(name=$($computerSystem.Name)))"
            $dn = $searcher.FindOne().Properties["distinguishedname"][0]
        }
        $ou = ($dn -split ',', 2)[1]
    } catch {
        Write-Host "Error retrieving the OU: $_"
    }
} else {
    $domain = "This computer is not joined to a domain"
    $workgroupName = $computerSystem.Workgroup
}


# Import the modules using a path relative to this script
. "$scriptDir\modules\windows\check_secpol.ps1"
. "$scriptDir\modules\windows\check_registry.ps1"
. "$scriptDir\modules\windows\shared_func.ps1"
. "$scriptDir\modules\windows\init.ps1"

$MBSS001 = Get-Policy -policyFile $policyFile -policyKey "PasswordHistorySize"
$MBSS002 = $accessPolicy | Select-String -Pattern "MaximumPasswordAge =" | ForEach-Object { [int]($_ -split '=')[1].Trim() }
$MBSS003 = Get-Policy -policyFile $policyFile -policyKey "MinimumPasswordAge" 
$MBSS004 = Get-Policy -policyFile $policyFile -policyKey "MinimumPasswordLength" 
$MBSS005 = Get-Policy-Status -policyFile $policyFile -policyKey "PasswordComplexity" 
$MBSS006 = Get-Policy-Status -policyFile $policyFile -policyKey "ClearTextPassword" 
$MBSS007 = Get-Policy -policyFile $policyFile -policyKey "LockoutDuration" 
$MBSS008 = Get-Policy -policyFile $policyFile -policyKey "LockoutBadCount" 
$MBSS009 = Get-Policy-Status -policyFile $policyFile -policyKey "AllowAdministratorLockout"
$MBSS010 = Get-PrivilegeSIDs -PrivilegeName "SeNetworkLogonRight" -sidToGroupMap $sidToGroupMap
$MBSS011 = Get-PrivilegeSIDs -PrivilegeName "SeIncreaseQuotaPrivilege" -sidToGroupMap $sidToGroupMap
$MBSS012 = Get-PrivilegeSIDs -PrivilegeName "SeRemoteInteractiveLogonRight" -sidToGroupMap $sidToGroupMap
$MBSS013 = Get-PrivilegeSIDs -PrivilegeName "SeBackupPrivilege" -sidToGroupMap $sidToGroupMap
$MBSS014 = Get-PrivilegeSIDs -PrivilegeName "SeSystemTimePrivilege" -sidToGroupMap $sidToGroupMap
$MBSS015 = Get-PrivilegeSIDs -PrivilegeName "SeTimeZonePrivilege" -sidToGroupMap $sidToGroupMap
$MBSS016 = Get-PrivilegeSIDs -PrivilegeName "SeCreateSymbolicLinkPrivilege" -sidToGroupMap $sidToGroupMap
$MBSS017 = Get-PrivilegeSIDs -PrivilegeName "SeDebugPrivilege" -sidToGroupMap $sidToGroupMap
$MBSS018 = Get-PrivilegeSIDs -PrivilegeName "SeRemoteShutdownPrivilege" -sidToGroupMap $sidToGroupMap
$MBSS019 = Get-PrivilegeSIDs -PrivilegeName "SeImpersonatePrivilege" -sidToGroupMap $sidToGroupMap
$MBSS020 = Get-PrivilegeSIDs -PrivilegeName "SeLoadDriverPrivilege" -sidToGroupMap $sidToGroupMap
$MBSS021 = Get-PrivilegeSIDs -PrivilegeName "SeLockMemoryPrivilege" -sidToGroupMap $sidToGroupMap
$MBSS022 = Get-PrivilegeSIDs -PrivilegeName "SeSecurityPrivilege" -sidToGroupMap $sidToGroupMap
$MBSS023 = Get-PrivilegeSIDs -PrivilegeName "SeAssignPrimaryTokenPrivilege" -sidToGroupMap $sidToGroupMap
$MBSS024 = Get-PrivilegeSIDs -PrivilegeName "SeRestorePrivilege" -sidToGroupMap $sidToGroupMap
$MBSS025 = Get-PrivilegeSIDs -PrivilegeName "SeShutdownPrivilege" -sidToGroupMap $sidToGroupMap
$MBSS026 = Get-PrivilegeSIDs -PrivilegeName "SeTakeOwnershipPrivilege" -sidToGroupMap $sidToGroupMap
$MBSS027 = check_notconnecteduser
$MBSS028 = Get-Policy-Status -policyFile $policyFile -policyKey "EnableGuestAccount"
$MBSS029 = Check_1_enable "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LimitBlankPasswordUse"
$MBSS030 = Get-Policy-Status -policyFile $policyFile -policyKey "AddPrinterDrivers"
$MBSS031 = Check_1_enable "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "RequireSignOrSeal"
$MBSS032 = Check_1_enable "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "SealSecureChannel"
$MBSS033 = Check_1_enable "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "SignSecureChannel"
$MBSS034 = Check_1_enable "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "RequireStrongKey"
$MBSS035 = Check_1_enable "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableCAD"
$MBSS036 = Check_1_enable "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DontDisplayLastUserName"
$MBSS037 = Get-RegistryValue "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "InactivityTimeoutSecs"
$MBSS038 = Get-RegistryValue -regKeyPath "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -regValueName "LegalNoticeText"
$MBSS039 = Get-RegistryValue -regKeyPath "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -regValueName "LegalNoticeCaption"
$MBSS040 = Get-RegistryValue -regKeyPath "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -regValueName "PasswordExpiryWarning"
$MBSS041 = Check_1_enable "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "RequireSecuritySignature"
$MBSS042 = Check_1_enable "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "EnableSecuritySignature"
$MBSS043 = Check_1_enable "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "EnablePlainTextPassword"
$MBSS044 = Get-RegistryValue -regKeyPath "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -regValueName "AutoDisconnect"
$MBSS045 = Check_1_enable "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "RequireSecuritySignature"
$MBSS046 = Check_1_enable "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "EnableSecuritySignature"
$MBSS047 = Check_1_enable "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "enableforcedlogoff"
$MBSS048 = if ((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMBServerNameHardeningLevel" -ErrorAction SilentlyContinue).SMBServerNameHardeningLevel -eq 1) { 
    "Accept if provided by client" 
} else { 
    "Not Configured" 
}

$MBSS049 = Get-Policy-Status -policyFile $policyFile -policyKey "LSAAnonymousNameLookup"
$MBSS050 = Check_1_enable   "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "DisableDomainCreds"
$MBSS051 = Get-RegistryValue -regKeyPath "HKLM:\SYSTEM\CurrentControlSet\Control\SecurePipeServers\Winreg\AllowedPaths" -regValueName "Machine"
$MBSS052 = Check_1_enable "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "RestrictNullSessAccess"
$MBSS053 = if ((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "restrictremotesam" -ErrorAction SilentlyContinue).restrictremotesam -eq "O:BAG:BAD:(A;;RC;;;BA)") { 
    "Administrators: Remote Access: Allow" 
} else { 
    "Not Configured" 
}

$MBSS054 = Check_1_enable "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "UseMachineId"
$MBSS055 = Check_1_enable "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "AllowNullSessionFallback"
$MBSS056 = Check_1_enable "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\pku2u" "AllowOnlineID"
$MBSS057 = Get-SupportedEncryptionTypes
$MBSS058 = Check_1_enable "HKLM:\System\CurrentControlSet\Control\Lsa" "NoLMHash"
$MBSS059 = Get-NetworkLANManagerSetting
$MBSS060 = if ((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LDAP" -Name "LDAPClientIntegrity" -ErrorAction SilentlyContinue).LDAPClientIntegrity -eq 1) { 
    "Negotiate signing" 
} else { 
    "Not Configured" 
}

$MBSS061 = Get-NTLMMinSecuritySetting -regKeyPath "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -regValueName "NTLMMinClientSec"
$MBSS062 = Get-NTLMMinSecuritySetting -regKeyPath "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -regValueName "NTLMMinServerSec"
$MBSS063 = if ((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "AuditReceivingNTLMTraffic" -ErrorAction SilentlyContinue).AuditReceivingNTLMTraffic -eq 2) { 
    "Enable auditing for all accounts" 
} else { 
    "Not Configured" 
}

$MBSS064 = Check_1_enable "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "FilterAdministratorToken"
$MBSS065 = Get-ConsentPromptBehaviorAdmin
$MBSS066 = Get-ConsentPromptBehaviorUser
$MBSS067 = Check_1_enable "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableInstallerDetection"
$MBSS068 = Check_1_enable "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableSecureUIAPaths"
$MBSS069 = Check_1_enable "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLUA"
$MBSS070 = Check_1_enable "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "PromptOnSecureDesktop"
$MBSS071 = Check-Service Spooler
$MBSS072 = Get-FWRegValue -regKeyPath "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" -regValueName "EnableFirewall"
$MBSS073 = Get-FWRegValue -regKeyPath "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" -regValueName "EnableFirewall"
$MBSS074 = Get-FWRegValue -regKeyPath "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PublicProfile" -regValueName "EnableFirewall"
$MBSS075 = Get-AuditPolSetting -subcategory "Logoff"
$MBSS076 = Get-AuditPolSetting -subcategory "Logon"
$MBSS077 = Get-AuditPolSetting -subcategory "Removable Storage"
$MBSS078 = Check_1_enable "HKLM:\SYSTEM\CurrentControlSet\Control\Print" "RpcAuthnLevelPrivacyEnabled"

$MBSS079 = if ((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\MRxSmb10" -Name "Start" -ErrorAction SilentlyContinue).Start -eq 4) { 
    "Enabled: Disable driver (recommended)" 
} else { 
    "Not Configured" 
}

$MBSS080 = Check_1_enable "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "SMB1"
$MBSS081 = Check_1_enable "HKLM:\SOFTWARE\Microsoft\Cryptography\Wintrust\Config" "EnableCertPaddingCheck" 
$DisableIPSourceRouting6 = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" -Name "DisableIPSourceRouting" -ErrorAction SilentlyContinue).DisableIPSourceRouting
$MBSS082 = if ($null -eq $DisableIPSourceRouting6) {
    "Not Configured"
} else {
    switch ($DisableIPSourceRouting6) {
        2       { "Enabled: Highest protection, source routing is completely disabled" }
        1       { "Enabled: Medium protection, source routed packets ignored when IP forwarding is enabled" }
        0       { "Disabled" }
        default { "Unknown value: $DisableIPSourceRouting6" }
    }
}

$MBSS083 = Check_1_enable "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" "EnableICMPRedirect" 

$MBSS084 = if ((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" -Name "TcpMaxDataRetransmissions" -ErrorAction SilentlyContinue).TcpMaxDataRetransmissions -eq 3) { 
    "Enabled: 3" 
} else { 
    "Not Configured" 
}

$MBSS085 = if ((Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TCPIP6\Parameters" -Name "DisabledComponents" -ErrorAction SilentlyContinue).DisabledComponents -eq 255) { 
    "0xff (255)" 
} else { 
    "Not Configured" 
}

$MBSS086 = if ((Get-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\Printers" -Name "RegisterSpoolerRemoteRpcEndPoint" -ErrorAction SilentlyContinue).RegisterSpoolerRemoteRpcEndPoint -eq 2) { 
    "Disabled"
} else { 
    "Enabled" 
}

$MBSS087 = if ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "NoWarningNoElevationOnInstall" -ErrorAction SilentlyContinue).NoWarningNoElevationOnInstall -eq 0) { 
    "Enabled: Show warning and elevation prompt" 
} else { 
    "Not Configured" 
}
$MBSS088 = if ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "UpdatePromptSettings" -ErrorAction SilentlyContinue).UpdatePromptSettings -eq 0) { 
    "Enabled: Show warning and elevation prompt" 
} else { 
    "Not Configured" 
}

$MBSS089 = Check_1_enable "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" "RestrictDriverInstallationToAdministrators"
$MBSS090 = if ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" -Name "CopyFilesPolicy" -ErrorAction SilentlyContinue).CopyFilesPolicy -eq 1) { 
    "Enabled: Limit Queue-specific files to Color profiles" 
} else { 
    "Not Configured" 
}

$MBSS091 = if ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" -Name "AllowEncryptionOracle" -ErrorAction SilentlyContinue).AllowEncryptionOracle -eq 0) { 
    "Enabled: Force Updated Clients" 
} else { 
    "Not Configured" 
}

$MBSS092 = Check_1_enable "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers" "DisableWebPnPDownload" 
$MBSS093 = Get-SupportDeviceAuthenticationStatus
$MBSS094 = Check_1_enable "HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures" "EnhancedAntiSpoofing"
$MBSS095 = Check_1_enable "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoDataExecutionPrevention"
$MBSS096 = Check_1_enable "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" "NoHeapTerminationOnCorruption"
$MBSS097 = Check_1_enable "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" "PreXPSP2ShellProtocolBehavior"
$MBSS098 = Check_1_enable "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" "DisableAntiSpyware"
$MBSS099 = Check_1_enable "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "DisablePasswordSaving"
$MBSS100 = Check_1_enable "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fSingleSessionPerUser"
$MBSS101 = Check_1_enable "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fDisableCcm"
$MBSS102 = Check_1_enable "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fDisableCdm"
$MBSS103 = Check_1_enable "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fDisableLPT"
$MBSS104 = Check_1_enable "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fDisablePNPRedir"
$MBSS105 = Check_1_enable "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fPromptForPassword"
$MBSS106 = if ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "SecurityLayer" -ErrorAction SilentlyContinue).SecurityLayer -eq 2) { 
    "Enabled: SSL" 
} else { 
    "Not Configured" 
}

$MBSS107 = Check_1_enable "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "UserAuthentication"
$MBSS108 = if ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MinEncryptionLevel" -ErrorAction SilentlyContinue).MinEncryptionLevel -eq 3) { 
     "Enabled: High Level"
} else { 
    "Not Configured" 
}
$MBSS109 = Get-RegistryTimeSetting -regKeyPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -regValueName "MaxIdleTime"
$MBSS110 = Get-RegistryTimeSetting -regKeyPath "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -regValueName "MaxDisconnectionTime"
$MBSS111 = Check_1_disabled "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "DeleteTempDirsOnExit"
$MBSS112 = Check_1_disabled "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "PerSessionTempDir"
$MBSS113 = Check_1_enable "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging"
$MBSS114 = Check_1_enable "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" "EnableTranscripting"
$MBSS115 = Check_1_enable "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" "AllowBasic"
$MBSS116 = Check_1_disabled "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoUpdate"
#$MBSS116 = Get-ScheduledInstallDayStatus
$MBSS117 = check_weak_tls
$MBSS118 = check_strong_tls
$MBSS119 = check_weak_des
$MBSS120 = check_weak_ssl
#$MBSS121 = Check-TrendMicro-Services
#$MBSS122 = "Review table below"
$MBSS121 = Check-Service Browser
$MBSS122 = Check-Service SharedAccess
$MBSS123 = Check-Service NetTcpPortSharing
$MBSS124 = Check-Service RasAuto
$MBSS125 = Check-Service RasMan
$MBSS126 = Check-Service RPCLocator
$MBSS127 = Check-Service TlntSvr
$MBSS128 = Check-Service TapiSrv

$user = Get-AllUserDetails
$process = Get-RunningProcesses
$netstat = Get-ListenPort
$Services = Get-RunningServices
$InstalledSoftware = Get-InstalledSoftware
$updates = Get-AvailableUpdates
$taskschedule = Check-TaskScheduler

# One <MBSSnnn> element per control; values are XML-escaped (&, <, > in registry text, OU names, etc.)
$mbssXml = foreach ($i in 1..128) {
    $id = 'MBSS{0:D3}' -f $i
    $val = Get-Variable -Name $id -ValueOnly -ErrorAction SilentlyContinue
    "        <$id>$(ConvertTo-XmlText $val)</$id>"
}

$xmlContent = @"
<?xml version="1.0" encoding="utf-8"?>
<Report>
    <SystemInformation>
        <Timestamp>$(ConvertTo-XmlText $timestamp)</Timestamp>
        <Hostname>$(ConvertTo-XmlText $hostname)</Hostname>
        <OS>$(ConvertTo-XmlText $os)</OS>
        <CurrentUser>$(ConvertTo-XmlText $currentUser)</CurrentUser>
        <IPAddresses>$(ConvertTo-XmlText $ipAddresses)</IPAddresses>
    </SystemInformation>
    <DomainStatus>$(ConvertTo-XmlText $domain)</DomainStatus>
    <OrganizationalUnit>$(ConvertTo-XmlText $ou)</OrganizationalUnit>
    <WorkgroupName>$(ConvertTo-XmlText $workgroupName)</WorkgroupName>
    <MBSS>
$($mbssXml -join "`r`n")
    </MBSS>
    <User>$user</User>
    <Process>$process</Process>
    <Services>$Services</Services>
    <Netstat>$netstat</Netstat>
    <InstalledSoftware>$InstalledSoftware</InstalledSoftware>
    <Updates>$updates</Updates>
    <TaskScheduler>$taskschedule</TaskScheduler>
</Report>
"@

# Make sure the result is well-formed before it is handed to report-win.py
try {
    [void]([xml]$xmlContent)
} catch {
    Write-Warning "The generated XML is not well-formed: $_"
}

# Save to XML file (UTF-8 without BOM) in the current directory
$xmlPath = Join-Path $currentDir "dump.xml"
[System.IO.File]::WriteAllText($xmlPath, $xmlContent, (New-Object System.Text.UTF8Encoding($false)))

# The exported policy is only a temporary working file
Remove-Item -Path $policyFile -Force -ErrorAction SilentlyContinue

Write-Host "Report saved to $xmlPath"
