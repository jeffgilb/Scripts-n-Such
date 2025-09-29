<#
.SYNOPSIS
    Automates the management of creating Autopilot branding Visual Studio Code workspaces.

.DESCRIPTION
    This script creates a Visual Studio Code workspace for creating Autopilot Branding Intune Win32 App packaging.
    It sets up the necessary folders, tasks, and scripts for creating and managing the Intune Win32 App package.
    It also includes functionality to download and update the IntuneWinAppUtil.exe tool and decode IntuneWin files.

.PARAMETER outDir
    The output directory where the workspace and files will be created. Default is the IntuneAP_Branding folder in the user's Documents directory.

.PARAMETER workSpaceName
    The name of the workspace to be created. Default is "AP_Branding".

.EXAMPLE
    .\AutopilotBrandingWorkspace.ps1 -outDir "AP_Branding" -workSpaceName "MyBrandingApp"
    Creates a workspace named "MyApp" in the "C:\Users\<you>\Documents\AP_Branding" directory.

.NOTES
    For best results, run this script in a PowerShell terminal with administrative privileges.
    Ensure that the required tools and dependencies are installed and available in the system PATH.

#>

param (
    [Parameter(Mandatory=$false)]
    [string]$workSpaceName = "AP_Branding",
    [Parameter(Mandatory=$false)]
    [string]$outDir = "IntuneAP_Branding"
)
Clear-Host
$myDocs = [Environment]::GetFolderPath("MyDocuments")
$outDir = Join-Path $myDocs $outDir
$path = Join-Path $outDir $workSpaceName
    if (-not (Test-Path -Path $path)) {
        New-Item -Path $path -ItemType Directory | Out-Null
    } else {
        $rand = Get-Random -Minimum 1 -Maximum 100
        $workSpaceName = $workSpaceName + "-" + $rand
        $path = Join-Path $outDir $workSpaceName
    }

# Create the source folder
New-Item -ItemType Directory -Path $path\source | Out-Null

# Define the folders to include in the workspace
$folders = @(
    @{
        path = $path
    }
)
# Define workspace settings (optional)
$settings = @{
    "editor.tabSize" = 4
    "files.exclude" = @{
        "*.code-workspace" = $true
        ".vscode" = $true
        ".git" = $true
    }
}

$tasks = @{
    version = "2.0.0"
    tasks = @(
        @{        
            label = "Generate IntuneWin file"
            type = "shell"
            command = "./.vscode/makeapp.ps1"
            problemMatcher = "[]"
        },
        @{
            label = "Update IntuneWinAppUtil.exe"
            type = "shell"
            command = "./.vscode/updateIntuneWinAppUtil.ps1"
            problemMatcher = "[]"
        },
        @{
            label = "Decode IntuneWin file"
            type = "shell"
            command = "./.vscode/decodeIntuneWin.ps1"
            problemMatcher = "[]"
        },
        @{
            label = "Download Autopilot Branding Latest Release"
            type = "shell"
            command = "./.vscode/dl_branding.ps1"
            problemMatcher = "[]"
        },
        @{
            label = "Download Latest AutopilotBrandingWorkspace.psm1"
            type = "shell"
            command = "./.vscode/dl_psm1.ps1"
            problemMatcher = "[]"
        }
    )
}

# Create the workspace JSON structure
$workspace = @{
    folders = $folders
    settings = $settings
    tasks = $tasks
}
# Convert the workspace structure to JSON
$workspaceJson = $workspace | ConvertTo-Json -Depth 10 -Compress

# Write the JSON to the .code-workspace file
Write-Output "Creating $workSpaceName workspace file..."

$workspaceFilePath = Join-Path $path "$workSpaceName.code-workspace"
Set-Content -Path $workspaceFilePath -Value $workspaceJson -Encoding UTF8 | Out-Null
Write-Host "  $workSpaceName.code-workspace created at $outDir"

# Put shortcut in outdir
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$outDir\$workSpaceName.lnk")
$Shortcut.TargetPath = "$workspaceFilePath"
$Shortcut.Save()

$taskFolderPath = Join-Path $path ".vscode"
# Ensure the .vscode folder exists
    if (-not (Test-Path -Path $taskFolderPath)) {
        New-Item -ItemType Directory -Path $taskFolderPath | Out-Null
        $hide = Get-Item $taskFolderPath -Force
        $hide.attributes = 'Hidden' 
    }

#------------------------------------------------ Grab IntuneWinAppUtil.exe -------------------------------------------------

# Download the latest version of the tool
# Define variables
$url = "https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool/archive/refs/heads/master.zip"
$output = "$($env:temp)\IntuneWinAppUtilMaster.zip"
$sourceFolder = "$($env:temp)\Microsoft-Win32-Content-Prep-Tool-master"
$sourceFile = "$($sourceFolder)\intunewinapputil.exe"
$destinationFolder = Join-Path $outDir $workSpaceName

# Download the latest version of the tool
Write-Output "Downloading the latest version of IntuneWinAppUtil.exe..."
$webClient = New-Object System.Net.WebClient
$webClient.DownloadFile($url, $output)
Start-Sleep -Seconds 3

# Extract the downloaded archive
Write-Output "  Extracting the downloaded archive"
Expand-Archive -Path $output -DestinationPath $env:temp -Force | Out-Null

# Copy the updated version to the destination folder
Write-Output "  Copying IntuneWinAppUtil.exe to the destination folder"
Copy-Item -Path $sourceFile -Destination $destinationFolder -Force

# Clean up temporary files
Write-Output "  Cleaning up temporary files"
Remove-Item -Path $sourceFolder -Recurse -Force
Remove-Item -Path $output -Force
#>

#-------------------------------------------- Grab the IntuneWinAppUtil Decoder ---------------------------------------------
# https://msendpointmgr.com/2019/01/18/how-to-decode-intune-win32-app-packages/

# Define variables
$url = "https://github.com/okieselbach/Intune/archive/refs/heads/master.zip"
$output = "$($env:temp)\IntuneWinAppUtilDecoder.zip"
$sourceFolder = "$($env:temp)\Intune-master"
$sourceFile = "$($sourceFolder)\IntuneWinAppUtilDecoder\IntuneWinAppUtilDecoder\bin\Release\IntuneWinAppUtilDecoder.exe"
$destinationFolder = $taskFolderPath

# Download the latest version of the tool
Write-Output "Downloading the latest version of IntuneWinAppUtilDecoder.exe..."
$webClient = New-Object System.Net.WebClient
$webClient.DownloadFile($url, $output)
Start-Sleep -Seconds 3

# Extract the downloaded archive
Write-Output "  Extracting the downloaded archive"
Expand-Archive -Path $output -DestinationPath $env:temp -Force | Out-Null

# Copy the updated version to the destination folder
Write-Output "  Copying IntuneWinAppUtilDecoder.exe to the destination folder"
Copy-Item -Path $sourceFile -Destination $destinationFolder -Force

# Clean up temporary files
Write-Output "  Cleaning up temporary files"
Remove-Item -Path $sourceFolder -Recurse -Force
Remove-Item -Path $output -Force
#>

Write-Output "Creating required files..."

# -------------------------------------------- Create the default setup.ps1 file -------------------------------------------
$setupScript = @"
<#
.SYNOPSIS

.DESCRIPTION
    
.PARAMETER     

.EXAMPLE

.NOTES
   Version      : 0.1
   Author       : 
   Last Modified:   
#>

#-------------------------------------------------------- Functions ---------------------------------------------------------
function Start-64bit {
    if ([Environment]::Is64BitProcess -eq `$false) {
        Write-Output "Re-launching as a 64-bit process..."
        `$arguments = "-NoProfile -ExecutionPolicy Bypass -File `$(`$MyInvocation.MyCommand.Path)"
        Start-Process powershell.exe -ArgumentList `$arguments -Wait
        Exit
    }
}
#------------------------------------------------------- Begin Script -------------------------------------------------------

# Start transcript to log the script output where Intune can grab it.
`$logDir = "`$(`$env:ProgramData)\Microsoft\IntuneManagementExtension\Logs"
`$logFile = "`$(`$logDir)\win32app.log"    #<-----------Rename this log file to something unique for each script
Start-Transcript `$logFile               #<-----------The existence of this log file can be used in an app detection rule

try {
    # Your script logic goes here
} catch {
    Write-Error "An error occurred: `$_"
}

Stop-Transcript 
Exit
"@
$setupScript | Out-File -FilePath "$path\source\setup.ps1" -Encoding UTF8 -Force
Write-Output "  Default setup file created"

#--------------------------------------------------- Create Make App Task ---------------------------------------------------
$makeApp = @"
# This script creates a .intunewin file and App Properties file for the IntuneWin32App package
function Get-MSIFileInformation {
    param(
        [Parameter(Mandatory = `$true, ValueFromPipeline = `$true)]
        [ValidateNotNullOrEmpty()]
        [System.IO.FileInfo[]]`$FilePath
    ) 
    `$msiOpenDatabaseModeReadOnly = 0
    `$properties = @('ProductName', 'Description', 'Manufacturer', 'ProductVersion', 'Information', 'Install', 'Uninstall', 'ProductCode')
    try {
        `$file = Get-ChildItem `$FilePath -ErrorAction Stop
    }
    catch {
        Write-Warning "Unable to get file `$FilePath `$(`$_.Exception.Message)"
        return
    }
    `$object = [PSCustomObject][ordered]@{
    }
    # Read property from MSI database
    `$windowsInstallerObject = New-Object -ComObject WindowsInstaller.Installer
    # Open read only    
    `$msiDatabase = `$windowsInstallerObject.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', `$null, `$windowsInstallerObject, @(`$file.FullName, `$msiOpenDatabaseModeReadOnly))
    foreach (`$property in `$properties) {
        `$view = `$null
        `$query = "SELECT Value FROM Property WHERE Property = '`$(`$property)'"
        `$view = `$msiDatabase.GetType().InvokeMember('OpenView', 'InvokeMethod', `$null, `$msiDatabase, (`$query))
        `$view.GetType().InvokeMember('Execute', 'InvokeMethod', `$null, `$view, `$null)
        `$record = `$view.GetType().InvokeMember('Fetch', 'InvokeMethod', `$null, `$view, `$null)
        try {
            `$value = `$record.GetType().InvokeMember('StringData', 'GetProperty', `$null, `$record, 1)
        }
        catch {
            Write-Verbose "Unable to get '`$property' `$(`$_.Exception.Message)"
            `$value = ''
        }
        `$object | Add-Member -MemberType NoteProperty -Name `$property -Value `$value
    }
    `$view.GetType().InvokeMember('Close', 'InvokeMethod', `$null, `$view, `$null)
    # Run garbage collection and release ComObject
    `$null = [System.Runtime.Interopservices.Marshal]::ReleaseComObject(`$windowsInstallerObject) 
    [System.GC]::Collect()
    return `$object  
} 
#-------------------------------------------------- Begin Script -----------------------------------------------------
#-------------------------------------------- Select the setup file to use -------------------------------------------
Add-Type -AssemblyName System.Windows.Forms
[System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms")|Out-Null
`$InitialDirectory = Join-Path -Path (Get-Location) -ChildPath "..\source"
`$InitialDirectory = [System.IO.Path]::GetFullPath(`$InitialDirectory)
`$fileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{
    Title = "Select the setup file to use."
    InitialDirectory = `$InitialDirectory
    Multiselect = `$false 
    Filter = 'Setup Files (ps1,msi,etc.)|*.*'
    }
`$result = `$fileBrowser.ShowDialog((New-Object System.Windows.Forms.Form -Property @{TopMost = `$true }))
    if (`$result -eq [Windows.Forms.DialogResult]::OK){
        `$setupFile = `$fileBrowser.SelectedPath
    }
    else {
        return
    }
`$setupFile  = `$fileBrowser.FileName;
`$setupFile = `$setupFile.Substring(`$setupFile.LastIndexOf("\") + 1)
`$setupFileBaseName = [System.IO.Path]::GetFileNameWithoutExtension(`$setupFile)
`$setupFileBaseName = `$setupFileBaseName -replace '\s', '_'
Start-Sleep -Seconds 2
try {
    `$file = Test-Path ".\Output\`$setupFileBaseName.intunewin"
    if(`$file){
        # If the file already exists, create a backup with the last modified date
        `$file = Get-Item ".\Output\`$setupFileBaseName.intunewin"
        `$lastModified = `$file.LastWriteTime.ToString("yyyyMMdd")
        `$bakFile = ".\Output\`$setupFileBaseName-`$lastModified.intunewin"
        If(Test-Path `$bakFile){
            # Only keep the most recent intunewin file from today.
            Remove-Item `$bakFile                
        }
        Copy-Item -Path `$file `$bakFile -Force
        .\intunewinapputil.exe -c .\Source -s "`$setupFile" -o .\output -q

        If(`$bakFile){Write-Output "Backup `$setupFileBaseName-`$lastModified.intunewin file created successfully in the output directory."}
    `$newFile = Get-Item ".\output\`$setupFileBaseName.intunewin"
        if(Test-Path `$newFile){
            Write-Output "`$setupFileBaseName.intunewin file created successfully in the output directory."
            Write-Output "You can now upload the new `$setupFileBaseName.intunewin file to Intune."
            Write-Output "Example command line: Powershell.exe -NoProfile -ExecutionPolicy ByPass -File setup.ps1"
        }
    }
    else {
        .\intunewinapputil.exe -c .\Source -s "`$setupFile" -o .\output -q
        `$file = Get-Item ".\Output\`$setupFileBaseName.intunewin"
        if(Test-Path `$file){
            Write-Output "`$setupFileBaseName.intunewin file created successfully in the output directory."
            Write-Output "You can now upload the new `$setupFileBaseName.intunewin file to Intune."
            Write-Output "Example command line: Powershell.exe -NoProfile -ExecutionPolicy ByPass -File setup.ps1"
        }
    }
} catch {
    Write-Error "An error occurred: `$_"
}

#--------------------------------------------- Create App Properties File --------------------------------------------

`$AppPropsFile = ".\App Properties.txt"
# Check if the App Properties file already exists
if (Test-Path `$AppPropsFile) {
    Write-Output "Existing App Properties.txt file found. Will not overwrite."
}Else{
    `$folderPath = ".\source\"
    # Search for an .msi file in the source folder
    `$MSIfile = Get-ChildItem -Path `$folderPath -Recurse -Filter *.msi
    If (`$MSIfile)  
    {
        `$msiInfo = Get-MSIFileInformation "`$(`$MSIfile.FullName)"
        `$msiInfo | Out-File ".\App Properties.txt"
        Write-Output "MSI properties saved to App Properties.txt."
        Write-Output ``n
    }Else {
            Write-Output "No MSI file found in the source directory. Creating default App Properties file."
            `$AppProps = @(
                "ProductName:   ",
                "Description:   ",
                "Manufacturer:  ",
                "ProductVersion:",
                "Information:   ",
                "Install:       ",
                "Uninstall:     ",
                "ProductCode:   "
            )
            Set-Content -Path ".\App Properties.txt" -Value `$AppProps
            Write-Output "Blank App Properties.txt file created."
            Write-Output ``n
        }
}

Exit
"@
$makeApp | Out-File -FilePath "$taskFolderPath\makeApp.ps1" -Encoding UTF8 -Force
Write-Output "  Generate IntuneWin File task created"

# -------------------------------------- Create Update IntuneWinAppUtil.exe Task Script -------------------------------------
$updateIntuneWinAppUtil = @"
# This script updates the IntuneWinAppUtil.exe tool by downloading the latest version from GitHub

# Define variables
`$url = "https://github.com/microsoft/Microsoft-Win32-Content-Prep-Tool/archive/refs/heads/master.zip"
`$output = "`$(`$env:temp)\IntuneWinAppUtilMaster.zip"
`$sourceFolder = "`$(`$env:temp)\Microsoft-Win32-Content-Prep-Tool-master"
`$sourceFile = "`$(`$sourceFolder)\intunewinapputil.exe"
`$parentDir = Get-Item . | Select-Object -ExpandProperty FullName
`$destinationFolder = `$parentDir
`$destinationFile = Join-Path `$parentDir "intunewinapputil.exe"

# Download the latest version of the tool
Write-Output "Downloading the latest version of IntuneWinAppUtil.exe..."
`$webClient = New-Object System.Net.WebClient
`$webClient.DownloadFile(`$url, `$output)
Start-Sleep -Seconds 3

# Extract the downloaded archive
Write-Output "Extracting the downloaded archive..."
Expand-Archive -Path `$output -DestinationPath `$env:temp -Force | Out-Null

# Check the existing version of the tool
if (Test-Path `$destinationFile) {
    `$fileInfo = (Get-Item `$destinationFile).VersionInfo
    Write-Output "Existing version: `$(`$fileInfo.InternalName) `$(`$fileInfo.FileVersion)."
} else {
    Write-Output "No current version of IntuneWinAppUtil.exe found."
}

# Copy the updated version to the destination folder
Write-Output "Copying the updated version to the destination folder..."
Copy-Item -Path `$sourceFile -Destination `$destinationFolder -Force

# Verify the updated version
if (Test-Path `$destinationFile) {
    `$fileInfo = (Get-Item `$destinationFile).VersionInfo
    Write-Output "Updated version: `$(`$fileInfo.InternalName) `$(`$fileInfo.FileVersion)."
} else {
    Write-Output "Failed to update IntuneWinAppUtil.exe."
}

# Clean up temporary files
Start-Sleep -Seconds 3
Write-Output "Cleaning up temporary files..."
Remove-Item -Path `$sourceFolder -Recurse -Force
Remove-Item -Path `$output -Force

Write-Output "Update process completed."
Write-Output ``n
"@
$updateIntuneWinAppUtil | Out-File -FilePath "$taskFolderPath\updateIntuneWinAppUtil.ps1" -Encoding UTF8 -Force
Write-Output "  Update IntuneWinAppUtil.exe task created"

# ---------------------------------------- Create Decode IntuneWin File Task Script -----------------------------------------
$decodeIntuneWinFile = @"
# This script is used to select an intunewin file and decode it using the IntuneWinAppUtilDecoder.exe tool.
# https://msendpointmgr.com/2019/01/18/how-to-decode-intune-win32-app-packages/
# The script uses a file dialog to allow the user to select the intunewin file and then decodes it.
#-------------------------------------------- Select the intunewin file to decode -------------------------------------------
Add-Type -AssemblyName System.Windows.Forms
[System.Reflection.Assembly]::LoadWithPartialName("System.windows.forms")|Out-Null
`$InitialDirectory1 = Join-Path -Path (Get-Location) -ChildPath "..\output"
`$InitialDirectory = [System.IO.Path]::GetFullPath(`$InitialDirectory1)
`$fileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{
    Title = "Select the intunewin file to decode."
    InitialDirectory = `$InitialDirectory1
    Multiselect = `$false 
    Filter = 'Intunewin Files (*.intunewin)|*.intunewin'
    }
`$result = `$fileBrowser.ShowDialog((New-Object System.Windows.Forms.Form -Property @{TopMost = `$true }))
    if (`$result -eq [Windows.Forms.DialogResult]::OK){
        `$IntuneWinApp = `$fileBrowser.SelectedPath
    }
    else {
        return
    }
`$IntuneWinApp  = `$fileBrowser.FileName;
#------------------------------------------------------ Decode it -----------------------------------------------------------
try {
        Set-Location `$PSScriptRoot
        Write-Output "Decoding `$IntuneWinApp"
        # Check if the IntuneWinAppUtilDecoder.exe exists
        `$decoderPath = Join-Path -Path `$PSScriptRoot -ChildPath "IntuneWinAppUtilDecoder.exe"
        if (-Not (Test-Path -Path `$decoderPath)) {
            Write-Error "IntuneWinAppUtilDecoder.exe not found in the script directory."
            return
        }
        # Run the IntuneWinAppUtilDecoder.exe with the selected intunewin file
        `$cmd = ".\IntuneWinAppUtilDecoder.exe '`$IntuneWinApp' /s"
        Write-Output "Running command: `$cmd"
        .\IntuneWinAppUtilDecoder.exe "`$IntuneWinApp" /s
        
        `$baseName = [System.IO.Path]::GetFileNameWithoutExtension(`$IntuneWinApp)
        `$file = Test-Path "..\output\`$baseName.decoded.zip"
        if(`$file){
            Write-Output "Intunewinapp successfully decoded as `$baseName.decoded.zip"
        }
        else {
            Write-Output "Failed to decode `$IntuneWinApp file."
        }
    }
catch {
    Write-Error "An error occurred: `$_"
}
Write-Output ``n
"@

$decodeIntuneWinFile | Out-File -FilePath "$taskFolderPath\decodeIntuneWin.ps1" -Encoding UTF8 -Force
Write-Output "  Decode IntuneWin File task created"

# ---------------------------------------- Create Download Autopilot Branding Latest Release Task Script -----------------------
$dl_Branding = @"
# This script downloads the latest release of Autopilot Branding from GitHub and extracts it to the current directory.
# It also removes unnecessary files and folders from the extracted directory.
param (
    [Parameter(Mandatory=`$false)]
    [string]`$outDir = ".\"
)

# Download latest Autopilot Branding release from github
`$repo = "mtniehaus/AutopilotBranding"
`$releases = "https://api.github.com/repos/`$repo/releases"
Write-Output ``n
Write-Output 'Determining latest Autopilot Branding release version'
`$tag = (Invoke-WebRequest `$releases | ConvertFrom-Json)[0].tag_name
Write-Output "  Latest release is `$tag"
`$file = "`$tag.zip"
`$download = "https://github.com/`$repo/archive/refs/tags/`$file"
`$TempDir = [System.IO.Path]::GetTempPath()
`$zip= "`$TempDir\`$tag.zip"

Write-Host "Dowloading latest release"
Write-Output "  `$download"
Invoke-WebRequest `$download -Out `$zip

Write-Output 'Extracting release files...'
Expand-Archive `$zip `$outDir

Write-Output 'Cleaning up temporary files...'
Remove-Item `$zip -Recurse -Force -ErrorAction SilentlyContinue 

Write-Output "Removing unnecessary files..."
`$path = Join-Path `$outDir "AutopilotBranding-`$tag"
Remove-Item -Path "`$path\.github" -Recurse -Force
Remove-Item -Path "`$path\.gitignore" -Force
# Remove-Item -Path "`$path\makeapp.cmd" -Force
# Remove-Item -Path "`$path\makeapp.ps1" -Force

Write-Output ``n
Exit
"@

$dl_Branding | Out-File -FilePath "$taskFolderPath\dl_branding.ps1" -Encoding UTF8 -Force
Write-Output "  Download Autopilot Branding Latest Release task created"

# --------------------------------------------------- Finish up -------------------------------------------------------------
Write-Output "Intune Win32 App VS Code workspace creation completed"
Write-Output `n
$openWorkspace = Read-Host "Do you want to open the workspace in VS Code now? [Y or N]"
if ($openWorkspace -eq "Y" -or $openWorkspace -eq "y") {
    try {
        #invoke-item $workspaceFilePath -ErrorAction SilentlyContinue
        code $workspaceFilePath #-NoNewWindow -ErrorAction SilentlyContinue
        Write-Output "Workspace opened in VS Code."
        Exit
    }
    catch {
        Write-Host "Unable to open VS Code. Please check if VS Code is installed."
        # Uncomment the line below to see the error details
        # Write-Output "Error: $_"
    }
        $portable = Read-Host "Do you want to download and use VSCode Portable to open the workspace? [Y or N]"
        if ($portable -eq "Y" -or $portable -eq "y") {
            $vscodePath = Join-Path $outDir ".VSCodePortable"
            if (-not (Test-Path -Path $vscodePath)) {
                New-Item -ItemType Directory -Path $vscodePath | Out-Null
            }
            
        # Find processor architecture for download link https://code.visualstudio.com/download
        $architecture = (Get-WMIObject -Class Win32_Processor).Architecture
        if ($architecture -eq 9) { #x64
            $vscodeZip = "https://code.visualstudio.com/sha/download?build=stable&os=win32-x64-archive"
        } elseif ($architecture -eq 5) { #arm64
            $vscodeZip = "https://code.visualstudio.com/sha/download?build=stable&os=win32-arm64-archive"
        } else {
            Write-Host "Unsupported architecture: $architecture" -ForegroundColor Red
        }    
            
        # Download VS Code portable .zip
        $vscodeFile = "VSCodePortable.zip"
        $vscodeOutFile = Join-Path $vscodePath $vscodeFile
        Write-Output "    Downloading and extracting VS Code Portable..."
        Invoke-WebRequest -Uri $vscodeZip -OutFile $vscodeOutFile -UseBasicParsing

        if (-not (Test-Path -Path $vscodeOutFile)) {
            Write-Host "Failed to download VS Code Portable. Please check your internet connection." -ForegroundColor Red
            Write-Host "Direct download link is $vscodeZip" -ForegroundColor
        }else {
        # Extract the downloaded .zip file
            Expand-Archive -Path $vscodeOutFile -DestinationPath $vscodePath -Force
        
        # Delete .zip file after extraction
            Remove-Item -Path $vscodeOutFile -Force
            Write-Output "VS Code Portable downloaded to $vscodePath"
        
        # Open workspace?
        $openWorkspace = Read-Host "Do you want to open the workspace in VS Code now? [Y or N]"
        if ($openWorkspace  -eq "Y" -or $openWorkspace  -eq "y") {
            $vscode = Join-Path "$vscodePath\Code.exe" 
            start-process $vscode -ArgumentList """$workspaceFilePath""" -NoNewWindow -ErrorAction SilentlyContinue
            Write-Output "Workspace opened in VS Code."
            Write-Output "You can also open the workspace later by double-clicking the $Shortcut created in $outDir"
            Write-Output `n
            Start-Sleep -seconds 10
            Exit
        }
    }
}
} else {
    Write-Output "You chose not to open the workspace." `n
    Write-Output "You can open the workspace later by double-clicking the $workSpaceName workspace shortcut created in $outDir" `n
    Write-Output "Good-bye." `n
}

Start-Sleep -Seconds 10
Exit


