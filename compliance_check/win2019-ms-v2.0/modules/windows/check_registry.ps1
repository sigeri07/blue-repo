function Check_1_enable {
    param(
        [string]$regKeyPath,
        [string]$regValueName,
        [string]$enabledText = "Enabled",
        [string]$disabledText = "Disabled",
        [string]$defaultText = "Not Defined"
    )
    
    if (Test-Path $regKeyPath) {
        $value = Get-ItemProperty -Path $regKeyPath -Name $regValueName -ErrorAction SilentlyContinue
        if ($value) {
            $val = $value.$regValueName
            if ($val -eq 1) {
                return $enabledText
            } elseif ($val -eq 0) {
                return $disabledText
            } else {
                return $defaultText
            }
        } else {
            return $defaultText
        }
    } else {
        return "$regKeyPath not found"
    }
}
function Check_1_disabled {
    param(
        [string]$regKeyPath,
        [string]$regValueName,
        [string]$enabledText = "Enabled",
        [string]$disabledText = "Disabled",
        [string]$defaultText = "Not Defined"
    )
    
    if (Test-Path $regKeyPath) {
        $value = Get-ItemProperty -Path $regKeyPath -Name $regValueName -ErrorAction SilentlyContinue
        if ($value) {
            $val = $value.$regValueName
            if ($val -eq 0) {
                return $enabledText
            } elseif ($val -eq 1) {
                return $disabledText
            } else {
                return $defaultText
            }
        } else {
            return $defaultText
        }
    } else {
        return "$regKeyPath not found"
    }
}
