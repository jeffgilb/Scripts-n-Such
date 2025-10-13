<#
.SYNOPSIS

.DESCRIPTION
    
.PARAMETER     

.EXAMPLE

.NOTES

#>

#-------------------------------------------------------- Functions ---------------------------------------------------------


#------------------------------------------------------- Begin Script -------------------------------------------------------
# Logging optional for remediations because the script output is displayed in the Intune portal's device status for your remediation.
# Logging enabled in this example where Intune can grab it if needed.
$logDir = "$($env:ProgramData)\Microsoft\IntuneManagementExtension\Logs" # This path is pulled when Intune collects diagnostics.
$logFile = "$($logDir)\autopatch_remediation.log" # Rename this log file.
#Start-Transcript $logFile

try {
    $WUkeys = @(
        "DoNotConnectToWindowsUpdateInternetLocations",
        "DisableWindowsUpdateAccess"
    )
    ForEach ($key in $WUkeys) {
        If (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate") {
            if((Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate).PSObject.Properties.Name -contains $key) {
                    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name $key -ErrorAction SilentlyContinue
                    Write-Output "Removed: $key"
                } Else{Write-Output "Key not found: $key"}
        } Else{ Write-Output "Path not found: HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\$key" }
    }

    $AUkeys = @(
        "NoAutoUpdate"
    )
    ForEach ($key in $AUkeys) {
        If (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU") {
            If ((Get-ItemProperty HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU).PSObject.Properties.Name -contains $key) {
                Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name $key -ErrorAction SilentlyContinue
                Write-Output "Removed: $key"    
                } Else{ Write-Output "Key not found: $key" }
            } Else { Write-Output "Path not found: HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\$key" } 
    }

Write-Output "Remediation completed."
#Stop-Transcript
Exit



























} catch {
    Write-Error "An error occurred: $_"
}

Stop-Transcript 
Exit
