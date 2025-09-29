# Display a custom header message when the module is imported
Write-Host `n"********************************************************************************************"  -ForegroundColor DarkCyan
Write-Host "   Autopilot Branding Optional Functions PowerShell Module successfully loaded."     -ForegroundColor DarkBlue
Write-Host "   Version: 1.0.0 | https://gitlab.us.bank-dns.com/windows-engineering/teams/gilbert" -ForegroundColor DarkBlue
Write-Host "********************************************************************************************"`n  -ForegroundColor DarkCyan

function Log() {
	[CmdletBinding()]
	param (
		[Parameter(Mandatory = $false)] [String] $message
	)

	$ts = get-date -f "yyyy/MM/dd hh:mm:ss tt"
	Write-Output "$ts $message"
}

function Disable-APv2 {
    # Disable extra APv2 pages (too late to do anything about the EULA), see https://call4cloud.nl/autopilot-device-preparation-hide-privacy-settings/
    try{
        $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE"
        New-ItemProperty -Path $registryPath -Name "DisablePrivacyExperience" -Value 1 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path $registryPath -Name "DisableVoice" -Value 1 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path $registryPath -Name "PrivacyConsentStatus" -Value 1 -PropertyType DWord -Force | Out-Null
        New-ItemProperty -Path $registryPath -Name "ProtectYourPC" -Value 3 -PropertyType DWord -Force | Out-Null
        Log '...APv2 extra pages disabled'
    } 
    catch {
        Log $_.Exception.Message
    }
}

function Set-LogViewer {
# Define the file extension and associated application
  $extension = ".log"
  $applicationPath = $($config.Config.LogViewer.Path)+'\'+$($config.Config.LogViewer.Viewer)
  # Check if the application exists
        If (-not (Test-Path -Path $applicationPath)) {
        Log "Log viewer executable not found at $applicationPath. Please check the configuration."
        return
        }
    # Loading NTUSER.DAT file to configure default HKCU registry settings.
    reg.exe load HKLM\TempUser "C:\Users\Default\NTUSER.DAT" | Out-Null
      # Set the default program for the .log file extension
      & reg.exe add "HKLM\TempUser\Software\Classes\$extension" /v "Default" /t REG_EXPAND_SZ /d "logfile" /f /reg:64 2>&1 | Out-Null
      # Create the association for the application
      & reg.exe add "HKLM\TempUser\Software\Classes\logfile\shell\open\command" /v "(Default)" /t REG_EXPAND_SZ /d "`"$applicationPath`"" /f /reg:64 2>&1 | Out-Null
    # Unloading NTUSER.DAT file
    reg.exe unload HKLM\TempUser | Out-Null
}

function Install-Onedrive {
    # Install OneDrive per machine
	if ($config.Config.OneDriveSetup) {
		$dest = "$($env:TEMP)\OneDriveSetup.exe"
		$client = new-object System.Net.WebClient
		if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") {
			$url = $config.Config.OneDriveARMSetup
		} else {
			$url = $config.Config.OneDriveSetup
		}
		Log "..Downloading OneDriveSetup: $url"
		$client.DownloadFile($url, $dest)
		Log "...Installing: $dest"
		$proc = Start-Process $dest -ArgumentList "/allusers /silent" -WindowStyle Hidden -PassThru
		$proc.WaitForExit()
		Log "...OneDriveSetup exit code: $($proc.ExitCode)"

	  # Loading NTUSER.DAT file to configure default HKCU registry settings.
		reg.exe load HKLM\TempUser "C:\Users\Default\NTUSER.DAT" | Out-Null
			Log "...Making sure the Run key exists"
			& reg.exe add "HKLM\TempUser\Software\Microsoft\Windows\CurrentVersion\Run" /f /reg:64 2>&1 | Out-Null
			& reg.exe query "HKLM\TempUser\Software\Microsoft\Windows\CurrentVersion\Run" /reg:64 2>&1 | Out-Null
			Log "...Changing OneDriveSetup value to point to the machine wide EXE"
			# Quotes are so problematic, we'll use the more risky approach and hope garbage collection cleans it up later
			Set-ItemProperty -Path "HKLM:\TempUser\Software\Microsoft\Windows\CurrentVersion\Run" -Name "OneDriveSetup" -Value """C:\Program Files\Microsoft OneDrive\Onedrive.exe"" /background" | Out-Null
	  # Unloading NTUSER.DAT file
		reg.exe unload HKLM\TempUser | Out-Null  
	}
}


function Remove-Apps {
    # Remove specified apps
    $removeApps = $config.Config.RemoveApps.App
    foreach ($app in $removeApps) {
        try {
            #Log "Removing app: $app"
            Get-AppxPackage -Name $app | Remove-AppxPackage -AllUsers
            Log "...Successfully removed: $app"
        } catch {
            Log "...Failed to remove app: $app. Error: $_"
        }
    }
}

function New-LAPSadmin{
    $UserID = Get-LocalUser -Name $($config.Config.LAPSadmin.Name) -ErrorAction SilentlyContinue
    If(!($UserID)){
        # Create Local User Account
            If ($($config.Config.LAPSadmin.Password) -eq "Random") {
            Log "Generating random password for LAPS Admin user."
            
            # Random Password Generator
            # Customize the length of the password
            $PasswordLength = $($config.Config.LAPSadmin.PasswordLength)

            # Define character sets
            $Uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            $Lowercase = "abcdefghijklmnopqrstuvwxyz"
            $Numbers = "0123456789"
            $SpecialChars = "!@#$%^&*()-_=+[]{}|;:,.<>?/"

            # Combine all character sets
            $AllChars = $Uppercase + $Lowercase + $Numbers + $SpecialChars

            # Ensure at least one character from each set
            $Password = (
                $Uppercase | Get-Random -Count 1
            ) + (
                $Lowercase | Get-Random -Count 1
            ) + (
                $Numbers | Get-Random -Count 1
            ) + (
                $SpecialChars | Get-Random -Count 1
            )

            # Fill the rest of the password with random characters
            $RemainingLength = $PasswordLength - $Password.Length
            $Password += -join ((1..$RemainingLength) | ForEach-Object { $AllChars | Get-Random })

            # Shuffle the password to randomize character order
            $PW = -join ($Password.ToCharArray() | Get-Random -Count $PasswordLength)

            #$pw = -join ((65..90) + (97..122) | Get-Random -Count $($config.Config.LAPSadmin.PasswordLength) | ForEach-Object {[char]$_})
            $LAPSPassword = ConvertTo-SecureString "$PW" -AsPlainText -Force
            }Else{
                Log "Using password specified in XML for LAPS Admin user."
                $LAPSPassword = ConvertTo-SecureString "$($config.Config.LAPSadmin.Password)" -AsPlainText -Force
            } 

        $params = @{
                Name        = "$($config.Config.LAPSadmin.Name)"
                Password    = $LAPSPassword
                FullName    = "$($config.Config.LAPSadmin.FullName)"
                Description = "$($config.Config.LAPSadmin.Description)"
                }                

        New-LocalUser @params | Out-Null

        # Add LAPS Admin user to the Administrators group
        Log "Adding LAPS Admin account to the Administrators group."
        Add-LocalGroupMember -Group "Administrators" -Member "$($config.Config.LAPSadmin.Name)"
    
        # Verify that the LAPS Admin user was created successfully
        $UserID = Get-LocalUser -Name $($config.Config.LAPSadmin.Name) -ErrorAction SilentlyContinue
            If($UserID){Log "Successfully created and configured the local LAPS Admin account."}
            Else{
                Log "Failed to create the local LAPS Admin account."
                }
            }     
       }           

#----------------------------------------- NOT IN USE -----------------------------------------

function Get-Updates {
# Updates & Inbox-App script
    if ($config.Config.SkipUpdates -ne 'true') {
        try {
            #Nuget v 2.8.5.201 is required to import mtniehaus's PS Gallery Script Update-InboxApp
            $minrequired = [version]'2.8.5.201'
            # OG script command: Check-NuGetProvider -MinimumVersion $minrequired
                Log "Installing NuGet provider"
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                Install-PackageProvider -Name NuGet -MinimumVersion $minrequired -Force -Scope AllUsers | Out-Null
            } catch {
            Log "Error updating NuGet"
        }
        try {
            Log 'Installing Update-InboxApp script'
            Install-Script Update-InboxApp -Force | Out-Null
            Log 'Updating inbox apps'
            # The path might not be set right to find this, so we'll hard-code the location
            Get-AppxPackage -AllUsers | Select-Object -Unique PackageFamilyName | . "C:\Program Files\WindowsPowerShell\Scripts\Update-InboxApp.ps1" -Verbose
        } catch {
            Log "Error updating in-box apps: $_"
        }
        try {
            Log 'Triggering Windows Update scan'
            $ns = 'Root\cimv2\mdm\dmmap'
            $class = 'MDM_EnterpriseModernAppManagement_AppManagement01'
            Get-CimInstance -Namespace $ns -ClassName $class | Invoke-CimMethod -MethodName UpdateScanMethod
        } catch {
            Log "Error triggering Windows Update scan: $_"
        }
    } else {
        Log 'Skipping updates'
    }
}

function Set-Proxy {
# Set the proxy settings for the system/default user
  reg.exe load HKLM\TempUser "C:\Users\Default\NTUSER.DAT" | Out-Null
    $proxyUrl = $config.Config.ProxyUrl
    $proxySettings = @{
        ProxyEnable = 1
        ProxyServer = $proxyUrl
        AutoConfigURL = $proxyUrl
    }
  # Set the proxy settings for the default user
    Set-ItemProperty -Path "HKLM:\TempUser\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "ProxyEnable" -Value $proxySettings.ProxyEnable -Type DWord | Out-Null
    Set-ItemProperty -Path "HKLM:\TempUser\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "ProxyServer" -Value $proxySettings.ProxyServer -Type String | Out-Null
    Set-ItemProperty -Path "HKLM:\TempUser\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name "AutoConfigURL" -Value $proxySettings.AutoConfigURL -Type String | Out-Null
  reg.exe unload HKLM\TempUser | Out-Null
}

function Test-Admin {
    # Check if the script is running with administrative privileges
    $isAdmin = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $isAdmin.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "This script requires administrative privileges. Please run as administrator." -ForegroundColor Red
        Exit 1
    }
}

function Test-64bit {
    # If we are running as a 32-bit process on an x64 system, re-launch as a 64-bit process
    if ("$env:PROCESSOR_ARCHITEW6432" -ne "ARM64") {
        if (Test-Path "$($env:WINDIR)\SysNative\WindowsPowerShell\v1.0\powershell.exe") {
            & "$($env:WINDIR)\SysNative\WindowsPowerShell\v1.0\powershell.exe" -ExecutionPolicy bypass -NoProfile -File "$PSCommandPath"
            Exit $lastexitcode
        }
    }
}
function New-Shortcuts{
    $config.Config.Shortcuts.Shortcut | ForEach-Object -ErrorAction 'SilentlyContinue' { 
    $value = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'):    " + $_.Name
    Add-Content -Path $logFilePath -Value $value
    $WshShell = New-Object -comObject WScript.Shell 
    $Shortcut = $WshShell.CreateShortcut($($_.Path))
    $Shortcut.Arguments = $_.Arguments
    $Shortcut.TargetPath = $_.TargetPath
    $Shortcut.WorkingDirectory = $_.WorkingDirectory
    $Shortcut.Save()
    }
 }

function edit-registry {
    #Log "Loading NTUSER.DAT file to configure registry settings."
    reg.exe load HKLM\TempUser "C:\Users\Default\NTUSER.DAT" | Out-Host    
 
    Try {
        $config.Config.RegKeys.RegKey | ForEach-Object { 
        # Ensure required paths are present
        If (-not (Test-Path -Path $_.Path)) {
            $create = "Path does not exist. Creating key: "
            $message = $create + $_.Path
            Log $message
            New-item -Path $_.Path -Force
            
            #Create entry after path is created
            $update = 'Updating registry to: '
            $message = $update + $_.Comment
            Log $message
            New-ItemProperty -Path $_.Path -Name $_.Key -PropertyType $_.PropertyType -Value $_.Value -Force

            }
        Else {
            $update = 'Updating registry to: '
            $message = $update + $_.Comment
            Log $message
            New-ItemProperty -Path $_.Path -Name $_.Key -PropertyType $_.PropertyType -Value $_.Value -Force
            }   
        }
    } 
    Catch {
            $errMsg = $_.Exception.Message
            Log $errMsg
    }
 
 #Log "Unloading NTUSER.DAT file."
 reg.exe unload HKLM\TempUser | Out-Host
}

function uninstall-apps {
    [Xml]$Config = Get-Content $fullPathToXML
        # Gather list of built-in apps to remove from config file
        $uninstallPackages = $config.Config.RemovePackages.App
        # Gather list of installed apps to remove from config file
        $uninstallPrograms = $config.Config.RemovePrograms.App
        # Find installed apps to remove
        $InstalledPackages = Get-AppxPackage -AllUsers | Where-Object {($UninstallPackages -contains $_.Name)}
        $ProvisionedPackages = Get-AppxProvisionedPackage -Online | Where-Object {($UninstallPackages -contains $_.DisplayName)}
        $InstalledPrograms = Get-Package | Where-Object {$UninstallPrograms -contains $_.Name}
        
        # List undiscovered apps 
        $UninstallPackages | ForEach-Object {
            If (($_ -notin $InstalledPackages.Name) -and ($_ -notin $ProvisionedPackages.DisplayName)) {
                Log "App not found: [$_]"
            }
        }
        
        # Remove provisioned packages first
        ForEach ($ProvPackage in $ProvisionedPackages){
        
            # Log "Attempting to remove provisioned package: [$($ProvPackage.DisplayName)]..."
            Try {
                Remove-AppxProvisionedPackage -PackageName $ProvPackage.PackageName -Online -ErrorAction Stop > $null
                Log "Successfully removed provisioned package: [$($ProvPackage.DisplayName)]"
            }
            Catch {
                Log "Warning: Failed to remove provisioned package: [$($ProvPackage.DisplayName)]"
            }
        }
        
        # Remove appx packages
        ForEach ($AppxPackage in $InstalledPackages){
        
            # Log "Attempting to remove Appx package: [$($AppxPackage.Name)]..."
            Try {
                Remove-AppxPackage -Package $AppxPackage.PackageFullName -AllUsers -ErrorAction Stop > $null
                Log "Successfully removed Appx package: [$($AppxPackage.Name)]"
            }
            Catch {
                Log "Warning: Failed to remove Appx package: [$($AppxPackage.Name)]"
            }
        }
        
        # Remove installed programs
        $InstalledPrograms | ForEach-Object {
        
            # Log "Attempting to uninstall: [$($_.Name)]..."
            Try {
                $_ | Uninstall-Package -AllVersions -Force -ErrorAction Stop > $null
                Log "Successfully uninstalled: [$($_.Name)]"
            }
            Catch {
                Log "Warning: Failed to uninstall: [$($_.Name)]"
            }
          }
    }

function New-AutologonUser{
        # Change default user image
        $accountPics = 'C:\ProgramData\Microsoft\User Account Pictures'
        Get-Item $accountPics\user.png | Rename-Item -NewName { $_.Name -replace '.png','.png.bak' } -Force
        # Copy user image to AutopilotBranding folder during autopilot branding stage
        Copy-Item -Path "$($env:ProgramData)\AutopilotBranding\user.png" -Destination $accountPics\user.png -Force

        $UserID = Get-LocalUser -Name $($config.Config.NewUser.Name) -ErrorAction SilentlyContinue
        If(!($UserID)){
           Log "New User [$($config.Config.NewUser.Name)] not found."
           # Create Local User Account
           Log "Creating New User local account: $($config.Config.NewUser.Name)."
           # Setting as global variable so it can be used later with scheduled tasks
           $global:pw = -join ((65..90) + (97..122) | Get-Random -Count $($config.Config.NewUser.PasswordLength) | ForEach-Object {[char]$_})
           $Password = ConvertTo-SecureString "$pw" -AsPlainText -Force
            
           $params = @{
                Name        = "$($config.Config.NewUser.Name)"
                Password    = $Password
                FullName    = "$($config.Config.NewUser.FullName)"
                Description = "$($config.Config.NewUser.Description)"
                AccountNeverExpires	= 1
                PasswordNeverExpires = 1
                }
                
           New-LocalUser @params

           # TEST ONLY
           # Add-LocalGroupMember -Group "Administrators" -Member "$($config.Config.NewUser.Name)"
    
           $UserID = Get-LocalUser -Name $($config.Config.NewUser.Name) -ErrorAction SilentlyContinue
           If($UserID){Log "Successfully created the $($config.Config.MTCUser.Name) local account."}
           Else{
               Log "Failed to create the $($config.Config.NewUser.Name) local account."
            }

        }
        Else{
            Log "New User found."
        } 
    
        # Configure AutoAdminLogon
        $regKeyPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
        $property = 'DefaultUserName'
        $propertyExists = (Get-ItemProperty $regkeypath).PSObject.Properties.Name -contains $property
        
        If($propertyExists){
            # if $propertyExists, check to see if it's set to config.xml user value
            $currentValue = (Get-ItemProperty -Path $regKeyPath -Name 'DefaultUserName').DefaultUserName
            $NewUserName = $($config.Config.NewUser.Name)
                          
            If ($currentValue -eq $NewUserName){
                Log "Autologon is already configured for $($config.Config.NewUser.Name)."
            }
            ElseIf ($currentValue -ne $NewUserName){
                # Reconfigure autologon
                Log "Autologon configured, but not for MTC. Reconfiguring."
                Log "Running Autologon64 to configure autologon for $($config.Config.NewUser.Name)."
                $userName = """$($config.Config.NewUser.Name)"""
                $domain = """."""
                Start-Process -FilePath "$($env:ProgramData)\AutopilotBranding\Autologon64.exe" -NoNewWindow -Wait -ArgumentList "/accepteula", $userName, $domain, $pw
                
                # GIVES FALSE NEGATIVE FOR SOME REASON: Validate it worked
                $currentValue = (Get-ItemProperty -Path $regKeyPath -Name 'DefaultUserName').DefaultUserName
                If($currentValue -eq $NewUserName){Log "Successfully configured autologon for $($config.Config.NewUser.Name)."}
                Else{
                    Log "Failed to configure autologon for $($config.Config.NewUser.Name)."
                }
            }
        }
        Else{
            #Autologon not configured.
            Log "Autologon not configured. Configuring."
            Log "Running Autologon64 to configure autologon for $($config.Config.NewUser.Name)."
            $userName = """$($config.Config.NewUser.Name)"""
            $domain = """."""
            Start-Process -FilePath "$($env:ProgramData)\AutopilotBranding\Autologon64.exe" -NoNewWindow -Wait -ArgumentList "/accepteula", $userName, $domain, $pw
            
            #Validate it worked
            $currentValue = (Get-ItemProperty -Path $regKeyPath -Name 'DefaultUserName').DefaultUserName
            If($currentValue -eq $NewUserName){Log "Successfully configured autologon for $($config.Config.NewUser.Name)."}
            Else{
                Log "Failed to configure autologon for $($config.Config.NewUser.Name)."
                # Throws false positives for some reason
            }
        }
    }

function Set-ScheduledTask{
    $scheduledTasks = Get-ChildItem -Path .\SchTskXML -Recurse | Where-Object {$_.PSIsContainer -eq $false}  
    
    ForEach ($task in $scheduledTasks){
        
        Try {
            $XMLname = $task.Name
            $taskName = $($task.BaseName)
            write-host $XMLname
            Log "Attempting to register scheduled task: $($task.BaseName)..."
            Register-ScheduledTask -xml (Get-Content .\SchTskXML\$XMLname | Out-String) -TaskName $taskName -Force
        }
        Catch {
            write-host $_.Exception.Message
            Log "Warning: Failed to create the $taskName scheduled task."
        }
    }
}    

function New-EventLog{
    New-EventLog -LogName 'Autopilot Configuration' -Source 'Autopilot-Config'
    # Restart Windows Event Log service so we can write to it immediately.
    Restart-Service -Name EventLog -Force
}

function exit-code{
    # This checks that new user is set as autologon
        $regKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
        $account = (Get-ItemProperty -Path $regKeyPath -Name DefaultUserName).DefaultUserName
        Try {
            If ($account -eq $($config.Config.User.Name)) { # Soft reboot because autoadminlogon is already configured.
                Return 3010
                }
            Else { # Hard reboot to allow autoadminlogon.
                Return 1641
                }   
            } 
            Catch {
                $errMsg = $_.Exception.Message
                Log $errMsg
            }
    }

function Set-Services {
    $DisabledCount = 0
    $AlreadyDisabledCount = 0
    $NotInstalledCount = 0
    
    $config.Config.Services.SVC | ForEach-Object { 
      $LocalServices = Get-Service -Name $_ -ErrorAction SilentlyContinue
      if ($LocalServices) {
        if ($LocalServices.StartType -ne 'Disabled') {
            Set-Service $_ -StartupType Disabled 
            Write-Host "Service $_ is now disabled."  -ForegroundColor Red
            $DisabledCount++
    
        } else {
            Write-Host "Service $_ is already disabled." -ForegroundColor Green
            $AlreadyDisabledCount++
        }   
        } else {
        Write-Host "Service $_ is not installed." -ForegroundColor Green
        $NotInstalledCount++
        }
      }
    
        Log "`nConfigured $DisabledCount services as 'Disabled'."
        Log "$AlreadyDisabledCount services were already disabled and $NotInstalledCount were not installed."
    
    }

    

# New edits to validate

function Enable-WindowsFeature {
    $InstalledCount = 0
    $AlreadyInstalledCount = 0
    $NotAvailableCount = 0
    
    $config.Config.AddFeatures.Feature | ForEach-Object { 
      $LocalFeature = Get-WindowsOptionalFeature -Online -FeatureName $_ -ErrorAction SilentlyContinue
      if ($LocalFeature) {
        if ($LocalFeature.State -ne 'Enabled') {
            Enable-WindowsOptionalFeature -Online -FeatureName $_ -NoRestart
            Write-Host "Windows Feature $_ is now enabled."  -ForegroundColor Green
            $InstalledCount++
    
        } else {
            Write-Host "Windows Feature $_ is already enabled." -ForegroundColor Green
            $AlreadyInstalledCount++
        }   
        } else {
        Write-Host "Windows Feature $_ is not available." -ForegroundColor Green
        $NotAvailableCount++
        }
      }
    
        Log "`nConfigured $InstalledCount Windows Features as 'Enabled'."
        Log "$AlreadyInstalledCount Windows Features were already enabled and $NotAvailableCount were not available."
    
}

function Disable-WindowsFeature {
    $DisabledCount = 0
    $AlreadyDisabledCount = 0
    $NotInstalledCount = 0
    
    $config.Config.DisableOptionalFeatures.Feature | ForEach-Object { 
      $LocalFeature = Get-WindowsOptionalFeature -Online -FeatureName $_ -ErrorAction SilentlyContinue
      if ($LocalFeature) {
        if ($LocalFeature.State -ne 'Disabled') {
            Disable-WindowsOptionalFeature -Online -FeatureName $_ -NoRestart | Out-Null
            Write-Host "...Windows Feature $_ is now disabled."  -ForegroundColor Red
            $DisabledCount++
    
        } else {
            Write-Host "...Windows Feature $_ is already disabled." -ForegroundColor Green
            $AlreadyDisabledCount++
        }   
        } else {
        Write-Host "...Windows Feature $_ is not installed." -ForegroundColor Green
        $NotInstalledCount++
        }
      }
    
        Log "`nConfigured $DisabledCount Windows Features as 'Disabled'."
        Log "$AlreadyDisabledCount Windows Features were already disabled and $NotInstalledCount were not installed."
    
}

function Set-DefaultApps {
    # Set default apps based on the Associations.xml file
    $associationsFile = "$($config.Config.DefaultApps)"
    if (Test-Path -Path $associationsFile) {
        Log "Setting default apps from $associationsFile"
        try {
            $xmlContent = Get-Content -Path $associationsFile -Raw
            $xmlContent | Out-File -FilePath "$env:TEMP\Associations.xml" -Encoding UTF8
            Add-AppxPackage -Register "$env:TEMP\Associations.xml" -DisableDevelopmentMode
            Log "Default apps set successfully."
        } catch {
            Log "Error setting default apps: $_"
        }
    } else {
        Log "Associations file not found: $associationsFile"
    }
}

function Install-WingetApp {
    # Install apps using Winget
    if ($config.Config.SkipWingetInstall -ine "true") {
        Log "Installing optional apps via Winget"
        $wingetApps = $config.Config.WinGetInstall.Id
        foreach ($app in $wingetApps) {
            try {
                Log "...Installing app: $app"
                Start-Process -FilePath "winget" -ArgumentList "install", "--id", $app, "--silent" -Wait
                Log "...Successfully installed: $app"
            } catch {
                Log "...Failed to install app: $app. Error: $_"
            }
        }
    } else {
        Log "Skipping optional app installations via Winget"
    }
}

function Set-DefaultAppAssociations {
    # Set default app file associations
    $defaultApps = $config.Config.DefaultApps.App
    foreach ($app in $defaultApps) {
        try {
      } catch {
            Log "Failed to set default app for: $($app.FileType). Error: $_"
        }
    }
}

function Remove-WindowsCapability {
    # Remove specified capabilities
    $removeCapabilities = $config.Config.RemoveCapabilities.Capability
    foreach ($capability in $removeCapabilities) {
        try {
            Log "Removing capability: $capability"
            Remove-WindowsCapability -Online -Name $capability -ErrorAction Stop
            Log "Successfully removed capability: $capability"
        } catch {
            Log "Failed to remove capability: $capability. Error: $_"
        }
    }
}

