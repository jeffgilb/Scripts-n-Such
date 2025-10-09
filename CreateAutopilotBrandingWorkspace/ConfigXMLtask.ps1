# Define the path where the XML file will be saved
$outputFile = "$PSScriptRoot\config.xml" 

# Create an XML document object
$xmlDoc = New-Object System.Xml.XmlDocument
# Create the root element
$root = $xmlDoc.CreateElement("Config")
$xmlDoc.AppendChild($root)

# Add version info
$versionInfo = $xmlDoc.CreateElement("VersionInfo")
$root.AppendChild($versionInfo)

$VersionInformation = @("Name","Version", "Author", "Description")
ForEach ($version in $VersionInformation){
# write-host $version
    $version = $xmlDoc.CreateElement($version)
    $version.InnerText = ' '
    $versionInfo.AppendChild($version) | Out-Null
}

# Path to the module manifest file (.psd1)
$manifestPath = "$PSScriptRoot\AP_Functions.psd1"
$moduleManifest = Import-PowerShellDataFile -Path $manifestPath
# Add FunctionFlag info
$FunctionFlags = $xmlDoc.CreateElement("FunctionFlags")
$root.AppendChild($FunctionFlags)
$FunctionFlags.SetAttribute("PSM1_Version", "$($moduleManifest.ModuleVersion)")
import-module "$PSScriptRoot\AP_Functions.psm1"     
$functions = get-command -module AP_Functions | Select-Object -ExpandProperty Name
ForEach ($function in $functions){
    $flag = $xmlDoc.CreateElement($function)
    $flag.InnerText = 'False'
    $FunctionFlags.AppendChild($flag) | Out-Null
}

# Add Features info
$addFeatures = $xmlDoc.CreateElement("AddFeatures")
$root.AppendChild($addFeatures)
    $addFeature = $xmlDoc.CreateElement("Feature")
    $addFeature.InnerText = ' '
    $addFeatures.AppendChild($addFeature)

# Default Apps
$defaultApps = $xmlDoc.CreateElement("DefaultApps")
$defaultApps.InnerText = ' '
$root.AppendChild($DefaultApps)

# Disable Optional Features
$disableFeatures = $xmlDoc.CreateElement("DisableOptionalFeatures")
$root.AppendChild($disableFeatures)
    $disableFeature = $xmlDoc.CreateElement("Feature")
    $disableFeature.InnerText = ' '
    $disableFeatures.AppendChild($disableFeature)

# Create folder structure
$folders = $xmlDoc.CreateElement("Folders")
$folders.InnerText = ' '
$root.AppendChild($folders)

# Language
$language = $xmlDoc.CreateElement("Language")
$language.InnerText = ' '
$root.AppendChild($language)

# OEM Info
$oem = $xmlDoc.CreateElement("OEMInfo")
$root.AppendChild($oem) 
$OEMInformation = @("Manufacturer","Model", "SupportURL", "SupportPhone", "SupportHours", "Logo")
ForEach ($info in $OEMInformation){ 
    $info = $xmlDoc.CreateElement($info)
    $info.InnerText = ' '
    $oem.AppendChild($info) | Out-Null
}

# OneDrive Setup
$oneDrive = $xmlDoc.CreateElement("OneDriveSetup")
$oneDrive.InnerText = ' https://go.microsoft.com/fwlink/?linkid=844652'
$root.AppendChild($oneDrive)
$oneDriveArm = $xmlDoc.CreateElement("OneDriveArmSetup")
$oneDriveArm.InnerText = 'https://go.microsoft.com/fwlink/?linkid=228208'    
$root.AppendChild($oneDriveArm)

# Proxy Settings
$proxy = $xmlDoc.CreateElement("ProxyURL")
$proxy.InnerText = ' '
$root.AppendChild($proxy)   

# Registry Keys to Modify
$registry = $xmlDoc.CreateElement("RegKeys")
$root.AppendChild($registry)    
    $regKey = $xmlDoc.CreateElement("RegKey")
    $regKey.InnerText = ' '
    $registry.AppendChild($regkey)

# Remove Apps
$removeApps = $xmlDoc.CreateElement("RemoveApps")
$root.AppendChild($removeApps)    
$removeMe = @("Microsoft.WindowsFeedbackHub","Microsoft.AV1VideoExtension","Microsoft.BingNews","Microsoft.BingSearch","Microsoft.BingWeather","Microsoft.GetHelp","Microsoft.Getstarted",
    "Microsoft.GamingApp","Microsoft.Messaging","Microsoft.Microsoft3DViewer","Microsoft.MicrosoftJournal","Microsoft.MicrosoftOfficeHub","Microsoft.MicrosoftSolitaireCollection",
    "Microsoft.MixedReality.Portal","Microsoft.MPEG2VideoExtension","Microsoft.News","Microsoft.Office.Lens","Microsoft.SkypeApp","Microsoft.Xbox.TCUI","Microsoft.XboxApp",
    "Microsoft.XboxGameOverlay","Microsoft.XboxGamingOverlay","Microsoft.XboxGamingOverlay_5.721.10202.0_neutral_~_8wekyb3d8bbwe","Microsoft.XboxIdentityProvider","Microsoft.XboxSpeechToTextOverlay",
    "Microsoft.ZuneMusic","Microsoft.ZuneVideo","MicrosoftCorporationII.MicrosoftFamily","MicrosoftCorporationII.QuickAssist","MicrosoftWindows.CrossDevice")

ForEach ($app in $removeMe){
    $removeApp = $xmlDoc.CreateElement("App")
    $removeApp.InnerText = "$app"
    $removeApps.AppendChild($removeApp) | Out-Null
}

# Windows Capabilities to Remove
$winCapability = $xmlDoc.CreateElement("RemoveCapability")
$root.AppendChild($winCapability)    
    $capability = $xmlDoc.CreateElement("Capability")
    $capability.InnerText = ' '
    $winCapability.AppendChild($capability)

# Registered Owner
$regOwner = $xmlDoc.CreateElement("RegisteredOwner")
$regOwner.InnerText = ' '
$root.AppendChild($regOwner)

# Registered Organization
$regOrg = $xmlDoc.CreateElement("RegisteredOrganization")
$regOrg.InnerText = ' '
$root.AppendChild($regOrg)

# Time Zone
$tz = $xmlDoc.CreateElement("TimeZone")
$tz.InnerText = ' '
$root.AppendChild($tz)

# Winget Install
$winGet = $xmlDoc.CreateElement("WingetInstall")
$root.AppendChild($winGet)    
    $id = $xmlDoc.CreateElement("Id")
    $id.InnerText = ' '
    $winGet.AppendChild($id)

# Save the XML document to a file
$xmlDoc.Save($outputFile)

# Output success message
Write-Host "XML file created successfully at $outputFile"
