param( $path )
If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs -path $pwd" -Verb RunAs
    Exit
}
Set-Location $path
Write-Output "Starting in $pwd"

Function WaitForKey {
    Write-Output "`nPress any key to continue..."
    [Console]::ReadKey($true) | Out-Null
}

Function Restart {
    Write-Output "Restarting in 10 seconds..."
    Start-Sleep -Seconds 10
    Restart-Computer
}

$tweaks = @(
    ### Privacy ###
    "DisableTelemetry",
    "DisableWiFiSense",
    "DisableSmartScreen",
    "DisableWebSearch",
    "DisableAppSuggestions",
    "DisableActivityHistory",
    "DisableBackgroundApps",
    "DisableLocation",
    "DisableFeedback",
    "DisableTailoredExperiences",
    "DisableAdvertisingID",
    # "DisableCortana",
    "DisableErrorReporting",
    "SetP2PUpdateDisable",
    "DisableDiagTrack",
    "DisableWAPPush",
    "DisableRecentFiles",

    ### Security Tweaks ###
    "SetUACLow",
    "DisableSMB1",
    "SetCurrentNetworkPrivate",
    "DisableConnectionSharing",
    "DisableDefenderCloud",
    "EnableDotNetStrongCrypto",
    "EnableF8BootMenu",
    "DisableRecoveryAndReset",
    "SetDEPOptIn",

    ### Service Tweaks ###
    "DisableMaintenanceWakeUp",
    "DisableSharedExperiences",
    "DisableRemoteAssistance",
    "DisableAutorun",
    "DisableStorageSense",
    "DisableMapUpdates",
    "DisableDefragmentation",
    "DisableSuperfetch",

    ### UI Tweaks ###
    "ShowTaskManagerDetails",
    "ShowFileOperationsDetails",
    "HideTaskbarSearch",
    "HideTaskbarPeopleIcon",
    "HideRecentlyAddedApps",
    "UnpinTaskbarIcons",
    # "EnableDarkTheme",
    "EnableVerboseStatus",
    "DisableF1HelpKey",

    ### Explorer UI Tweaks ###
    "ShowKnownExtensions",
    "ShowHiddenFiles",
    "ShowEmptyDrives",
    "DisableSharingWizard",
    "HideSyncNotifications",
    "SetExplorerThisPC",
    "ShowUserFolderOnDesktop",
    "HideDesktopFromThisPC",
    "HideDownloadsFromThisPC",
    "HideDocumentsFromThisPC",
    "HidePicturesFromThisPC",
    "HideVideosFromThisPC",
    "HideMusicFromThisPC",
    "Hide3DObjectsFromThisPC",
    "HideDocumentsFromExplorer",
    "HidePicturesFromExplorer",
    "HideVideosFromExplorer",
    "HideMusicFromExplorer",
    "HideIncludeInLibraryMenu",
    "HideGiveAccessToMenu",
    "HideShareMenu",
    "DisableThumbsDBOnNetwork",

    ### Application Tweaks ###
    "UninstallOneDrive",
    "UninstallMsftBloat",
    # "UninstallWindowsStore",
    "DisableXboxFeatures",
    "EnableFullscreenOptims",
    "DisableEdgePreload",
    "DisableEdgeShortcutCreation",
    "UninstallMediaPlayer",
    "SetPhotoViewerAssociation",
    "UninstallXPSPrinter",
    "RemoveFaxPrinter",

    ### Custom functions ###
    "MorePrivacyTweaks",
    "AddEncryptionToContext",
    "CustomizePath",
    "InstallChocolatey",
    "InstallChocoPackages",
    "CleanContextMenu",
    "CleanStartup",
    "CleanDirectories",
    "CopyFiles",
    "SetBackground",
    "QuickAccessPinning",
    "TaskbarPinning",
    # "SetFileExtensions",
    "Shutup10",
    "InstallPsCorePackages",
    "InstallEXEs",
    "OpenManualWindows",
    "WaitForKey"
    # "Restart"
)

# # # # # # # # # # # #
# Privacy
# # # # # # # # # # # #
Function DisableTelemetry {
    Write-Output "Disabling Telemetry..."
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -PropertyType DWord -Value 0 | Out-Null
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -PropertyType DWord -Value 0 | Out-Null
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -PropertyType DWord -Value 0 | Out-Null
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Force | Out-Null
    }
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" -Name "AllowBuildPreview" -PropertyType DWord -Value 0 | Out-Null
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Force | Out-Null
    }
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" -Name "NoGenTicket" -PropertyType DWord -Value 1 | Out-Null
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Force | Out-Null
    }
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows" -Name "CEIPEnable" -PropertyType DWord -Value 0 | Out-Null
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Force | Out-Null
    }
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -PropertyType DWord -Value 0 | Out-Null
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableInventory" -PropertyType DWord -Value 1 | Out-Null
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP" -Force | Out-Null
    }
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\AppV\CEIP" -Name "CEIPEnable" -PropertyType DWord -Value 0 | Out-Null
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Force | Out-Null
    }
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\TabletPC" -Name "PreventHandwritingDataSharing" -PropertyType DWord -Value 1 | Out-Null
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" -Force | Out-Null
    }
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" -Name "AllowLinguisticDataCollection" -PropertyType DWord -Value 0 | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null
}

Function DisableWiFiSense {
    Write-Output "Disabling Wi-Fi Sense..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
    }
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -PropertyType DWord -Value 0 | Out-Null
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Force | Out-Null
    }
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -PropertyType DWord -Value 0 | Out-Null
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Force | Out-Null
    }
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "AutoConnectAllowedOEM" -PropertyType DWord -Value 0 | Out-Null
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" -Name "WiFISenseAllowed" -PropertyType DWord -Value 0 | Out-Null
}

Function DisableSmartScreen {
    Write-Output "Disabling SmartScreen Filter..."
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableSmartScreen" -PropertyType DWord -Value 0 | Out-Null
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Force | Out-Null
    }
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" -Name "EnabledV9" -PropertyType DWord -Value 0 | Out-Null
}

Function DisableWebSearch {
    Write-Output "Disabling Bing Search in Start Menu..."
    New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -PropertyType DWord -Value 0 | Out-Null
    New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -PropertyType DWord -Value 0 | Out-Null
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
    }
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "DisableWebSearch" -PropertyType DWord -Value 1 | Out-Null
}

Function DisableAppSuggestions {
    Write-Output "Disabling Application suggestions..."
    New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -PropertyType DWord -Value 0 | Out-Null
    New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -PropertyType DWord -Value 0 | Out-Null
    New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -PropertyType DWord -Value 0 | Out-Null
    New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -PropertyType DWord -Value 0 | Out-Null
    New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -PropertyType DWord -Value 0 | Out-Null
    New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310093Enabled" -PropertyType DWord -Value 0 | Out-Null
    New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-314559Enabled" -PropertyType DWord -Value 0 | Out-Null
    New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -PropertyType DWord -Value 0 | Out-Null
    New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -PropertyType DWord -Value 0 | Out-Null
    New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -PropertyType DWord -Value 0 | Out-Null
    New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -PropertyType DWord -Value 0 | Out-Null
    New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -PropertyType DWord -Value 0 | Out-Null
    New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -PropertyType DWord -Value 0 | Out-Null
    New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -PropertyType DWord -Value 0 | Out-Null
    New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -PropertyType DWord -Value 0 | Out-Null
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
    }
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -PropertyType DWord -Value 1 | Out-Null
    # Empty placeholder tile collection in registry cache and restart Start Menu process to reload the cache
    If ([System.Environment]::OSVersion.Version.Build -ge 17134) {
        $key = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\*windows.data.placeholdertilecollection\Current"
        New-ItemProperty -Force -Path $key.PSPath -Name "Data" -PropertyType Binary -Value $key.Data[0..15] | Out-Null
        Stop-Process -Name "ShellExperienceHost" -Force -ErrorAction SilentlyContinue
    }
}

Function DisableActivityHistory {
    Write-Output "Disabling Activity History..."
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -PropertyType DWord -Value 0 | Out-Null
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -PropertyType DWord -Value 0 | Out-Null
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -PropertyType DWord -Value 0 | Out-Null
}

Function DisableBackgroundApps {
    Write-Output "Disabling Background application access..."
    Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Exclude "Microsoft.Windows.Cortana*", "Microsoft.Windows.ShellExperienceHost*" | ForEach-Object {
        New-ItemProperty -Force -Path $_.PsPath -Name "Disabled" -PropertyType DWord -Value 1 | Out-Null
        New-ItemProperty -Force -Path $_.PsPath -Name "DisabledByUser" -PropertyType DWord -Value 1 | Out-Null
    }
}

Function DisableLocation {
    Write-Output "Disabling location services..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Force | Out-Null
    }
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocation" -PropertyType DWord -Value 1 | Out-Null
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" -Name "DisableLocationScripting" -PropertyType DWord -Value 1 | Out-Null
}

Function DisableFeedback {
    Write-Output "Disabling Feedback..."
    If (!(Test-Path "HKCU:\Software\Microsoft\Siuf\Rules")) {
        New-Item -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Force | Out-Null
    }
    New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -PropertyType DWord -Value 0 | Out-Null
    New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "PeriodInNanoSeconds" -PropertyType DWord -Value 0 | Out-Null
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -PropertyType DWord -Value 1 | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null
}

Function DisableTailoredExperiences {
    Write-Output "Disabling Tailored Experiences..."
    If (!(Test-Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent")) {
        New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
    }
    New-ItemProperty -Force -Path "HKCU:\Software\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -PropertyType DWord -Value 1 | Out-Null
}

Function DisableAdvertisingID {
    Write-Output "Disabling Advertising ID..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" | Out-Null
    }
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -PropertyType DWord -Value 1 | Out-Null
}

Function DisableCortana {
    New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaEnabled" -PropertyType DWord -Value 0 | Out-Null
    Write-Output "Disabling Cortana..."
    If (!(Test-Path "HKCU:\Software\Microsoft\Personalization\Settings")) {
        New-Item -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Force | Out-Null
    }
    New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -PropertyType DWord -Value 0 | Out-Null
    If (!(Test-Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore")) {
        New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
    }
    New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -PropertyType DWord -Value 1 | Out-Null
    New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -PropertyType DWord -Value 1 | Out-Null
    New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -PropertyType DWord -Value 0 | Out-Null
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" -Name "Value" -PropertyType DWord -Value 0 | Out-Null
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
    }
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -PropertyType DWord -Value 0 | Out-Null
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Force | Out-Null
    }
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\InputPersonalization" -Name "AllowInputPersonalization" -PropertyType DWord -Value 0 | Out-Null
}

Function DisableErrorReporting {
    Write-Output "Disabling Error reporting..."
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -PropertyType DWord -Value 1 | Out-Null
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null
}

Function SetP2PUpdateDisable {
    Write-Output "Disabling Windows Update P2P optimization..."
    # Method used since 1511
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" | Out-Null
    }
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -PropertyType DWord -Value 100 | Out-Null
}

Function DisableDiagTrack {
    Write-Output "Stopping and disabling Connected User Experiences and Telemetry Service..."
    Stop-Service "DiagTrack"
    Set-Service "DiagTrack" -StartupType Disabled
}

Function DisableWAPPush {
    Write-Output "Stopping and disabling Device Management WAP Push Service..."
    Stop-Service "dmwappushservice"
    Set-Service "dmwappushservice" -StartupType Disabled
}

Function DisableRecentFiles {
    Write-Output "Disabling recent files lists..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
    }
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsHistory" -PropertyType DWord -Value 1 | Out-Null
}

# # # # # # # # # # # #
# Security
# # # # # # # # # # # #
Function SetUACLow {
    Write-Output "Lowering UAC level..."
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -PropertyType DWord -Value 0 | Out-Null
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -PropertyType DWord -Value 0 | Out-Null
}

Function DisableSMB1 {
    Write-Output "Disabling SMB 1.0 protocol..."
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
}

Function SetCurrentNetworkPrivate {
    Write-Output "Setting current network profile to private..."
    Set-NetConnectionProfile -NetworkCategory Private
}

Function DisableConnectionSharing {
    Write-Output "Disabling Internet Connection Sharing..."
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Network Connections" -Name "NC_ShowSharedAccessUI" -PropertyType DWord -Value 0 | Out-Null
}

Function DisableDefenderCloud {
    Write-Output "Disabling Windows Defender Cloud..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Force | Out-Null
    }
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SpynetReporting" -PropertyType DWord -Value 0 | Out-Null
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -Name "SubmitSamplesConsent" -PropertyType DWord -Value 2 | Out-Null
}

Function EnableDotNetStrongCrypto {
    Write-output "Enabling .NET strong cryptography..."
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -PropertyType DWord -Value 1 | Out-Null
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -PropertyType DWord -Value 1 | Out-Null
}

Function EnableF8BootMenu {
    Write-Output "Enabling F8 boot menu options..."
    bcdedit /set `{current`} BootMenuPolicy Legacy | Out-Null
}

Function DisableRecoveryAndReset {
    Write-Output "Disabling System Recovery and Factory reset..."
    reagentc /disable 2>&1 | Out-Null
}

Function SetDEPOptIn {
    Write-Output "Setting Data Execution Prevention (DEP) policy to OptIn..."
    bcdedit /set `{current`} nx OptIn | Out-Null
}


# # # # # # # # # # # #
# Services
# # # # # # # # # # # #
Function DisableMaintenanceWakeUp {
    Write-Output "Disabling nightly wake-up for Automatic Maintenance..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
    }
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -PropertyType DWord -Value 0 | Out-Null
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" -Name "WakeUp" -PropertyType DWord -Value 0 | Out-Null
}

Function DisableSharedExperiences {
    Write-Output "Disabling Shared Experiences..."
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP" | Out-Null
    }
    New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP" -Name "RomeSdkChannelUserAuthzPolicy" -PropertyType DWord -Value 0 | Out-Null
}

Function DisableRemoteAssistance {
    Write-Output "Disabling Remote Assistance..."
    New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -PropertyType DWord -Value 0 | Out-Null
}

Function DisableAutorun {
    Write-Output "Disabling Autorun for all drives..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
    }
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -PropertyType DWord -Value 255 | Out-Null
}

Function DisableStorageSense {
    Write-Output "Disabling Storage Sense..."
    Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Recurse -ErrorAction SilentlyContinue
}

Function DisableMapUpdates {
    Write-Output "Disabling automatic Maps updates..."
    Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0
}

Function DisableDefragmentation {
    Write-Output "Disabling scheduled defragmentation..."
    Disable-ScheduledTask -TaskName "Microsoft\Windows\Defrag\ScheduledDefrag" | Out-Null
}

Function DisableSuperfetch {
    Write-Output "Stopping and disabling Superfetch service..."
    Stop-Service "SysMain"
    Set-Service "SysMain" -StartupType Disabled
}

# # # # # # # # # # # #
# UI
# # # # # # # # # # # #

Function ShowTaskManagerDetails {
    Write-Output "Showing task manager details..."
    $taskmgr = Start-Process -WindowStyle Hidden -FilePath taskmgr.exe -PassThru
    $timeout = 30000
    $sleep = 100
    Do {
        Start-Sleep -Milliseconds $sleep
        $timeout -= $sleep
        $preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
    } Until ($preferences -or $timeout -le 0)
    Stop-Process $taskmgr
    If ($preferences) {
        $preferences.Preferences[28] = 0
        New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -PropertyType Binary -Value $preferences.Preferences | Out-Null
    }
}

Function ShowFileOperationsDetails {
    Write-Output "Showing file operations details..."
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" | Out-Null
    }
    New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -PropertyType DWord -Value 1 | Out-Null
}

Function HideTaskbarSearch {
    Write-Output "Hiding Taskbar Search icon / box..."
    New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -PropertyType DWord -Value 0 | Out-Null
}

Function HideTaskbarPeopleIcon {
    Write-Output "Hiding People icon..."
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" | Out-Null
    }
    New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -PropertyType DWord -Value 0 | Out-Null
}

Function HideRecentlyAddedApps {
    Write-Output "Hiding 'Recently added' list from the Start Menu..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
    }
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HideRecentlyAddedApps" -PropertyType DWord -Value 1 | Out-Null
}

Function UnpinTaskbarIcons {
    Write-Output "Unpinning all Taskbar icons..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Name "Favorites" -Type Binary -Value ([byte[]](255))
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" -Name "FavoritesResolve" -ErrorAction SilentlyContinue
}

Function EnableDarkTheme {
    Write-Output "Enabling Dark Theme..."
    New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -PropertyType DWord -Value 0 | Out-Null
}

Function EnableVerboseStatus {
    Write-Output "Enabling verbose startup/shutdown status messages..."
    If ((Get-CimInstance -Class "Win32_OperatingSystem").ProductType -eq 1) {
        New-ItemProperty -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus" -PropertyType DWord -Value 1 | Out-Null
    }
    Else {
        Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "VerboseStatus" -ErrorAction SilentlyContinue
    }
}

Function DisableF1HelpKey {
    Write-Output "Disabling F1 Help key..."
    If (!(Test-Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win32")) {
        New-Item -Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win32" -Force | Out-Null
    }
    New-ItemProperty -Force -Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win32" -Name "(Default)" -PropertyType "String" -Value "" | Out-Null
    If (!(Test-Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64")) {
        New-Item -Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64" -Force | Out-Null
    }
    New-ItemProperty -Force -Path "HKCU:\Software\Classes\TypeLib\{8cec5860-07a1-11d9-b15e-000d56bfe6ee}\1.0\0\win64" -Name "(Default)" -PropertyType "String" -Value "" | Out-Null
}

# # # # # # # # # # # #
# Explorer
# # # # # # # # # # # #
Function ShowKnownExtensions {
    Write-Output "Showing known file extensions..."
    New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -PropertyType DWord -Value 0 | Out-Null
}

Function ShowHiddenFiles {
    Write-Output "Showing hidden files..."
    New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -PropertyType DWord -Value 1 | Out-Null
}

Function ShowEmptyDrives {
    Write-Output "Showing empty drives (with no media)..."
    New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideDrivesWithNoMedia" -PropertyType DWord -Value 0 | Out-Null
}

Function DisableSharingWizard {
    Write-Output "Disabling Sharing Wizard..."
    New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "SharingWizardOn" -PropertyType DWord -Value 0 | Out-Null
}

Function HideSyncNotifications {
    Write-Output "Hiding sync provider notifications..."
    New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -PropertyType DWord -Value 0 | Out-Null
}

Function SetExplorerThisPC {
    Write-Output "Changing default Explorer view to This PC..."
    New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -PropertyType DWord -Value 1 | Out-Null
}

Function ShowUserFolderOnDesktop {
    Write-Output "Showing User Folder shortcut on desktop..."
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Force | Out-Null
    }
    New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -PropertyType DWord -Value 0 | Out-Null
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Force | Out-Null
    }
    New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -PropertyType DWord -Value 0 | Out-Null
}

Function HideDesktopFromThisPC {
    Write-Output "Hiding Desktop icon from This PC..."
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" -Recurse
}

Function HideDownloadsFromThisPC {
    Write-Output "Hiding Downloads icon from This PC..."
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}" -Recurse
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}" -Recurse
}

Function HideDocumentsFromThisPC {
    Write-Output "Hiding Documents icon from This PC..."
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}" -Recurse
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}" -Recurse
}

Function HidePicturesFromThisPC {
    Write-Output "Hiding Pictures icon from This PC..."
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -Recurse
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -Recurse
}

Function HideVideosFromThisPC {
    Write-Output "Hiding Videos icon from This PC..."
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -Recurse
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -Recurse
}

Function HideMusicFromThisPC {
    Write-Output "Hiding Music icon from This PC..."
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -Recurse
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -Recurse
}

Function Hide3DObjectsFromThisPC {
    Write-Output "Hiding 3D Objects icon from This PC..."
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse
}

Function HideDocumentsFromExplorer {
    Write-Output "Hiding Documents icon from Explorer namespace..."
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" -Name "ThisPCPolicy" -PropertyType String -Value "Hide" | Out-Null
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" -Name "ThisPCPolicy" -PropertyType String -Value "Hide" | Out-Null
}

Function HidePicturesFromExplorer {
    Write-Output "Hiding Pictures icon from Explorer namespace..."
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" -Name "ThisPCPolicy" -PropertyType String -Value "Hide" | Out-Null
}

Function HideVideosFromExplorer {
    Write-Output "Hiding Videos icon from Explorer namespace..."
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" -Name "ThisPCPolicy" -PropertyType String -Value "Hide" | Out-Null
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{35286a68-3c57-41a1-bbb1-0eae73d76c95}\PropertyBag" -Name "ThisPCPolicy" -PropertyType String -Value "Hide" | Out-Null
}

Function HideMusicFromExplorer {
    Write-Output "Hiding Music icon from Explorer namespace..."
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" -Name "ThisPCPolicy" -PropertyType String -Value "Hide" | Out-Null
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" -Name "ThisPCPolicy" -PropertyType String -Value "Hide" | Out-Null
}

Function HideIncludeInLibraryMenu {
    Write-Output "Hiding 'Include in library' context menu item..."
    If (!(Test-Path "HKCR:")) {
        New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
    }
    Remove-Item -Path "HKCR:\Folder\ShellEx\ContextMenuHandlers\Library Location"
}

Function HideGiveAccessToMenu {
    Write-Output "Hiding 'Give access to' context menu item..."
    If (!(Test-Path "HKCR:")) {
        New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
    }
    Remove-Item -LiteralPath "HKCR:\*\shellex\ContextMenuHandlers\Sharing"
    Remove-Item -Path "HKCR:\Directory\Background\shellex\ContextMenuHandlers\Sharing"
    Remove-Item -Path "HKCR:\Directory\shellex\ContextMenuHandlers\Sharing"
    Remove-Item -Path "HKCR:\Drive\shellex\ContextMenuHandlers\Sharing"
}

Function HideShareMenu {
    Write-Output "Hiding 'Share' context menu item..."
    If (!(Test-Path "HKCR:")) {
        New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
    }
    Remove-Item -LiteralPath "HKCR:\*\shellex\ContextMenuHandlers\ModernSharing"
}

Function DisableThumbsDBOnNetwork {
    Write-Output "Disabling creation of Thumbs.db on network folders..."
    New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "DisableThumbsDBOnNetworkFolders" -PropertyType DWord -Value 1 | Out-Null
}

# # # # # # # # # # # #
# Application
# # # # # # # # # # # #
Function UninstallOneDrive {
    Write-Output "Uninstalling OneDrive..."
    Stop-Process -Name "OneDrive" -Force
    Start-Sleep -s 2
    $onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
    If (!(Test-Path $onedrive)) {
        $onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
    }
    Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
    Start-Sleep -s 2
    Stop-Process -Name "explorer"
    Start-Sleep -s 2
    Remove-Item -Path "$env:USERPROFILE\OneDrive"  -Force -Recurse
    Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse
    Remove-Item -Path "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse
}

Function UninstallMsftBloat {
    Write-Output "Uninstalling default Microsoft applications..."
    Get-AppxPackage "Microsoft.BingWeather" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.GetHelp" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.Getstarted" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.Microsoft3DViewer" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.MicrosoftOfficeHub" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.MicrosoftSolitaireCollection" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.MicrosoftStickyNotes" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.MixedReality.Portal" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.MSPaint" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.Office.OneNote" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.People" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.SkypeApp" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.Wallet" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.WebMediaExtensions" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.WindowsAlarms" | Remove-AppxPackage
    # Get-AppxPackage "Microsoft.WindowsCamera" | Remove-AppxPackage
    Get-AppxPackage "microsoft.windowscommunicationsapps" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.WindowsFeedbackHub" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.WindowsMaps" | Remove-AppxPackage
    # Get-AppxPackage "Microsoft.Windows.Photos" | Remove-AppxPackage
    # Get-AppxPackage "Microsoft.WindowsSoundRecorder" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.YourPhone" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.ZuneMusic" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.ZuneVideo" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.ScreenSketch" | Remove-AppxPackage
}

Function UninstallWindowsStore {
    Write-Output "Uninstalling Windows Store..."
    Get-AppxPackage "Microsoft.DesktopAppInstaller" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.Services.Store.Engagement" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.StorePurchaseApp" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.WindowsStore" | Remove-AppxPackage
}

Function DisableXboxFeatures {
    Write-Output "Disabling Xbox features..."
    Get-AppxPackage "Microsoft.XboxApp" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.XboxIdentityProvider" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.XboxSpeechToTextOverlay" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.XboxGameOverlay" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.XboxGamingOverlay" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.Xbox.TCUI" | Remove-AppxPackage
    New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\GameBar" -Name "GameDVR_Enabled" -PropertyType DWord -Value 0 | Out-Null
    New-ItemProperty -Force -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -PropertyType DWord -Value 0 | Out-Null
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" | Out-Null
    }
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" -Name "AllowGameDVR" -Type DWord -Value 0 | Out-Null
}

Function EnableFullscreenOptims {
    Write-Output "Enabling Fullscreen optimizations..."
    New-ItemProperty -Force -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_DXGIHonorFSEWindowsCompatible" -PropertyType DWord -Value 0 | Out-Null
    Remove-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehavior" -ErrorAction SilentlyContinue
    New-ItemProperty -Force -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_FSEBehaviorMode" -PropertyType DWord -Value 0 | Out-Null
    New-ItemProperty -Force -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_HonorUserFSEBehaviorMode" -PropertyType DWord -Value 0 | Out-Null
}

Function DisableEdgePreload {
    Write-Output "Disabling Edge preload..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Force | Out-Null
    }
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "AllowPrelaunch" -PropertyType DWord -Value 0 | Out-Null
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" -Force | Out-Null
    }
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" -Name "AllowTabPreloading" -PropertyType DWord -Value 0 | Out-Null
}

Function DisableEdgeShortcutCreation {
    Write-Output "Disabling Edge shortcut creation..."
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "DisableEdgeDesktopShortcutCreation" -PropertyType DWord -Value 1 | Out-Null
}

Function UninstallMediaPlayer {
    Write-Output "Uninstalling Windows Media Player..."
    Disable-WindowsOptionalFeature -Online -FeatureName "WindowsMediaPlayer" -NoRestart | Out-Null
}

Function SetPhotoViewerAssociation {
    Write-Output "Setting Photo Viewer association for bmp, gif, jpg, png and tif..."
    If (!(Test-Path "HKCR:")) {
        New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
    }
    ForEach ($type in @("Paint.Picture", "giffile", "jpegfile", "pngfile")) {
        New-Item -Path $("HKCR:\$type\shell\open") -Force | Out-Null
        New-Item -Path $("HKCR:\$type\shell\open\command") | Out-Null
        New-ItemProperty -Force -Path $("HKCR:\$type\shell\open") -Name "MuiVerb" -PropertyType ExpandString -Value "@%ProgramFiles%\Windows Photo Viewer\photoviewer.dll,-3043" | Out-Null
        New-ItemProperty -Force -Path $("HKCR:\$type\shell\open\command") -Name "(Default)" -PropertyType ExpandString -Value "%SystemRoot%\System32\rundll32.exe `"%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll`", ImageView_Fullscreen %1" | Out-Null
    }
}

Function UninstallXPSPrinter {
    Write-Output "Uninstalling Microsoft XPS Document Writer..."
    Disable-WindowsOptionalFeature -Online -FeatureName "Printing-XPSServices-Features" -NoRestart | Out-Null
}

Function RemoveFaxPrinter {
    Write-Output "Removing Default Fax Printer..."
    Remove-Printer -Name "Fax"
}

# # # # # # # # # # # #
# Custom
# # # # # # # # # # # #
function MorePrivacyTweaks {
    Write-Output "Running more privacy tweaks..."
    New-ItemProperty -Force -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost' -name EnableWebContentEvaluation -PropertyType DWord -Value 0 | Out-Null
}

function AddEncryptionToContext {
    Write-Output "Adding encryption to explorer context..."
    New-ItemProperty -Force -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "EncryptionContextMenu" -PropertyType DWord -Value 1 | Out-Null
}

function CustomizePath {
    Write-Output "Customizing path..."
    $oldpath = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH).path
    $newpath = "$oldpath"
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment' -Name PATH -Value $newPath
}

function InstallChocolatey {
    Write-Output "Installing Chocolatey..."
    Set-ExecutionPolicy Bypass -Scope Process -Force; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    choco feature enable -n=allowGlobalConfirmation
}

function InstallChocoPackages {
    Write-Output "Installing Choco packages..."
    choco install vcredist2015 --version=14.0.24212.20160825
    choco install shutup10
    choco install 7zip chromium ccleaner vlc obs-studio vscode
    choco install ddu msiafterburner steam origin
    choco install powershell-core vscode
}

function CleanContextMenu {
    Write-Output "Cleaning up context menu..."
    Remove-Item -path "Registry::HKCR\.bmp\ShellNew" | Out-Null
    Remove-Item -path "Registry::HKCR\.contact\ShellNew" | Out-Null
    Remove-Item -path "Registry::HKCR\.zip\ShellNew" | Out-Null
    Remove-Item -path "Registry::HKCR\.rar\ShellNew" | Out-Null
    Remove-Item -path "Registry::HKCR\Folder\shellex\ContextMenuHandlers\PintoStartScreen" | Out-Null
    Remove-Item -path "Registry::HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}" | Out-Null
    Remove-Item -literalpath "Registry::HKCR\*\shellex\ContextMenuHandlers\{90AA3A4E-1CBA-4233-B8BB-535773D48449}" | Out-Null
    Remove-Item -literalpath "Registry::HKCR\*\shellex\ContextMenuHandlers\{a2a9545d-a0c2-42b4-9708-a0b2badd77c8}" | Out-Null
    Remove-Item -literalpath "Registry::HKCR\*\shellex\ContextMenuHandlers\PDFCreator.ShellContextMenu" | Out-Null
    Remove-Item -literalpath "Registry::HKCR\*\shellex\ContextMenuHandlers\SimpleShlExt"  | Out-Null
    Remove-Item -path "Registry::HKCR\Directory\shell\AddToPlaylistVLC" -Recurse | Out-Null
    Remove-Item -path "Registry::HKCR\Directory\shell\PlayWithVLC" -Recurse | Out-Null
}

function CleanStartup {
    Write-Output "Cleaning up startup programs..."
    Remove-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name Steam
}

function CleanDirectories {
    Write-Output "Cleaning up user directories..."
    Get-ChildItem -Path "$env:USERPROFILE\Desktop" -Include * -Recurse | ForEach-Object { $_.Delete() }
    Get-ChildItem -Path "$env:USERPROFILE\Documents" -Include * -Recurse | ForEach-Object { $_.Delete() }
    Remove-Item -Path "$env:USERPROFILE\Pictures" -Force -Recurse
    Remove-Item -Path "$env:USERPROFILE\Videos" -Force -Recurse
    Remove-Item -Path "$env:USERPROFILE\Music" -Force -Recurse
    Remove-Item -Path "$env:USERPROFILE\Favorites" -Force -Recurse
    Remove-Item -Path "$env:USERPROFILE\Links" -Force -Recurse
    Remove-Item -Path "$env:USERPROFILE\contacts" -Force -Recurse
    Remove-Item -Path "$env:USERPROFILE\3D Objects" -Force -Recurse
    # Get-ChildItem -Force -Path "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Start Menu" -Include * -Recurse | ForEach-Object { Remove-Item $_.FullName -Force -Recurse }
    # Get-ChildItem -Force -Path "$env:PROGRAMDATA\Microsoft\Windows\Start Menu" -Include * -Recurse | ForEach-Object { Remove-Item $_.FullName -Force -Recurse }
}

Function CopyFiles {
    Write-Output "Copying files to C: ..."
    Copy-Item ".\files\Users\user\*" -Destination "$env:USERPROFILE\" -Recurse -Force
    Copy-Item ".\files\Program Files\*" -Destination "$env:PROGRAMFILES\" -Recurse -Force
    Copy-Item ".\files\Program Files (x86)\*" -Destination "C:\Program Files (x86)\" -Recurse -Force
}

function QuickAccessPinning {
    Write-Output "Unpinning default quick access pins..."
    $QuickAccess = new-object -com shell.application
    $Objects = $QuickAccess.Namespace("shell:::{679f85cb-0220-4080-b29b-5540cc05aab6}").Items()
    $TargetObject = $Objects | Where-Object { $_.Path -eq "$env:USERPROFILE\Pictures" }
    if ($TargetObject) {
        $TargetObject.InvokeVerb("unpinfromhome")
    }
    $TargetObject = $Objects | Where-Object { $_.Path -eq "$env:USERPROFILE\Documents" }
    if ($TargetObject) {
        $TargetObject.InvokeVerb("unpinfromhome")
    }
}

function TaskbarPinning {
    Write-Output "Pinning to taskbar..."
    regedit /S taskband.reg
}

function SetFileExtensions {
    Write-Output "Setting file extensions mapping..."
    regedit /S fileexts.reg
}

function Shutup10 {
    Write-Output "Running Shutup10..."
    Start-Process -FilePath "$env:PROGRAMDATA\chocolatey\bin\OOSU10.exe" -ArgumentList "ooshutup10.cfg /quiet" -NoNewWindow -Wait
}

function InstallExes {
    Write-Output "Installing EXEs..."
    Start-Process files\setup\kombustor.exe -Wait
}

function OpenManualWindows {
    control /name Microsoft.IndexingOptions
    Start-Process -FilePath "C:\Program Files\Chromium\Application\chrome.exe"
}

$tweaks | ForEach-Object { Invoke-Expression $_ }
