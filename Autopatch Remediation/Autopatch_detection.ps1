<#
.SYNOPSIS

.DESCRIPTION
    
.PARAMETER     

.EXAMPLE

.NOTES

#>

try {
    $i = 0
    
    $WUkeys = @(
        "DoNotConnectToWindowsUpdateInternetLocations",
        "DisableWindowsUpdateAccess"
    )
    ForEach ($key in $WUkeys) {
        If (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate") {
            if((Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate).PSObject.Properties.Name -contains $key) {
                $i++
            } Else{Write-Output "Key not found: $key"}
        }
    }

    $AUkeys = @(
        "NoAutoUpdate"
    )
    ForEach ($key in $AUkeys) {
        If (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU") {
            if((Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU).PSObject.Properties.Name -contains $key) {
            $i++
            } Else{ Write-Output "Key not found: $key" }
        } 

    }
    
    if ( $i -gt 0 ) {
        Write-Output "Issues detected."
        Exit 1 # Detection: non-compliant
    } else {
        Write-Output "No issues detected."
        Exit 0 # Detection: compliant
    }
    
} catch {
    Write-Output "Error occurred: $_"
}



<#





    $regKeys = @(
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate",
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DoNotConnectToWindowsUpdateInternetLocations"
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "DisableWindowsUpdateAccess"



Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name ""
    )
    $r = 0
    ForEach ($regKey in $regKeys) {
        if (Test-Path $regKey) {
            $r++
            Write-Output "Registry key exists: $regKey"
        }
    }
    
    if( $r -gt 0 ) {
        Write-Output "Issues detected."
        Exit 1 # Detection: non-compliant
    } else {
        Write-Output "No issues detected."
        Exit 0 # Detection: compliant
    }
}


Exit

#>