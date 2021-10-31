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
    "DisableCortana",
    "DisableErrorReporting",
    "SetP2PUpdateDisable",
    "DisableDiagTrack",
    "DisableWAPPush",
    "DisableRecentFiles",

    ### Security Tweaks ###
    "SetUACLow",
    "DisableSharingMappedDrives",
    "DisableSMB1",
    # "EnableNetBIOS",
    "EnableLLMNR",
    "SetCurrentNetworkPrivate",
    "DisableConnectionSharing",
    "DisableDefenderCloud",
    "EnableDotNetStrongCrypto",
    "EnableF8BootMenu",
    "DisableRecoveryAndReset",

    ### Service Tweaks ###
    "EnableUpdateMSRT",
    "EnableUpdateDriver",
    "EnableUpdateAutoDownload",
    "DisableMaintenanceWakeUp",
    "DisableHomeGroups",
    "DisableSharedExperiences",
    "EnableClipboardHistory",
    "DisableRemoteAssistance",
    "EnableRemoteDesktop",
    "DisableAutorun",
    "DisableStorageSense",
    "DisableMapUpdates",
    "DisableDefragmentation",
    "DisableSuperfetch",
    "EnableHibernation",
    "EnableSleepTimeout",
    "EnableFastStartup",

    ### UI Tweaks ###
    "HideNetworkFromLockScreen",
    "ShowShutdownOnLockScreen",
    "ShowTaskManagerDetails",
    "ShowFileOperationsDetails",
    "DisableFileDeleteConfirm",
    "HideTaskbarSearch",
    "HideTaskbarPeopleIcon",
    "HideRecentlyAddedApps",
    "UnpinStartMenuTiles",
    "UnpinTaskbarIcons",
    "EnableDarkTheme",
    "EnableVerboseStatus",
    "DisableF1HelpKey",

    ### Explorer UI Tweaks ###
    "ShowKnownExtensions",
    "ShowHiddenFiles",
    "ShowEmptyDrives",
    "ShowEncCompFilesColor",
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
    "Hide3DObjectsFromExplorer",
    "HideIncludeInLibraryMenu",
    "HideGiveAccessToMenu",
    "HideShareMenu",
    "DisableThumbsDBOnNetwork",

    ### Application Tweaks ###
    "UninstallOneDrive",
    "UninstallMsftBloat",
    "UninstallWindowsStore",
    "UninstallThirdPartyBloat",
    "DisableXboxFeatures",
    "EnableFullscreenOptims",
    "DisableEdgePreload",
    "DisableEdgeShortcutCreation",
    "DisableMediaSharing",
    "UninstallMediaPlayer",
    "InstallPowerShellV2",
    "SetPhotoViewerAssociation",
    "RemovePhotoViewerOpenWith",
    "RemoveFaxPrinter",
    "UninstallFaxAndScan",

    ### Custom functions ###
    "MorePrivacyTweaks",
    "InstallChocolatey",
    "InstallChocoPackages",
    "CleanContextMenu",
    "CleanStartup",
    "CleanDirectories",
    "CopyFiles",
    "SetBackground",
    "QuickAccessPinning",
    "Shutup10",
    "InstallPsCorePackages",
    "InstallExes",
    "OpenManualWindows",
    "WaitForKey"
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
    If ([System.Environment]::OSVersion.Version.Build -eq 10240) {
        # Method used in 1507
        If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
            New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" | Out-Null
        }
        New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -PropertyType DWord -Value 0 | Out-Null
    }
    Else {
        # Method used since 1511
        If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization")) {
            New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" | Out-Null
        }
        New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" -Name "DODownloadMode" -PropertyType DWord -Value 100 | Out-Null
    }
}

Function DisableDiagTrack {
    Write-Output "Stopping and disabling Connected User Experiences and Telemetry Service..."
    Stop-Service "DiagTrack" -WarningAction SilentlyContinue
    Set-Service "DiagTrack" -StartupType Disabled
}

Function DisableWAPPush {
    Write-Output "Stopping and disabling Device Management WAP Push Service..."
    Stop-Service "dmwappushservice" -WarningAction SilentlyContinue
    Set-Service "dmwappushservice" -StartupType Disabled
}

Function DisableRecentFiles {
    Write-Output "Disabling recent files lists..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
    }
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRecentDocsHistory" -PropertyType DWord -Value 1 | Out-Null | Out-Null
}

# # # # # # # # # # # #
# Security
# # # # # # # # # # # #
Function SetUACLow {
    Write-Output "Lowering UAC level..."
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -PropertyType DWord -Value 0 | Out-Null
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -PropertyType DWord -Value 0 | Out-Null
}

Function DisableSharingMappedDrives {
    Write-Output "Disabling sharing mapped drives between users..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections" -ErrorAction SilentlyContinue
}

Function DisableSMB1 {
    Write-Output "Disabling SMB 1.0 protocol..."
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
}

Function EnableNetBIOS {
    Write-Output "Enabling NetBIOS over TCP/IP..."
    New-ItemProperty -Force "HKLM:\SYSTEM\CurrentControlSet\services\NetBT\Parameters\Interfaces\Tcpip*" -Name "NetbiosOptions" -PropertyType DWord -Value 0 | Out-Null
}

Function EnableLLMNR {
    Write-Output "Enabling LLMNR..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
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

# # # # # # # # # # # #
# Services
# # # # # # # # # # # #
Function EnableUpdateMSRT {
    Write-Output "Enabling Malicious Software Removal Tool offering..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MRT" -Name "DontOfferThroughWUAU" -ErrorAction SilentlyContinue
}

Function EnableUpdateDriver {
    Write-Output "Enabling driver offering through Windows Update..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontPromptForWindowsUpdate" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DriverUpdateWizardWuSearchEnabled" -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -ErrorAction SilentlyContinue
}

Function EnableUpdateAutoDownload {
    Write-Output "Enabling Windows Update automatic downloads..."
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUOptions" -ErrorAction SilentlyContinue
}

Function DisableMaintenanceWakeUp {
    Write-Output "Disabling nightly wake-up for Automatic Maintenance..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
    }
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -PropertyType DWord -Value 0 | Out-Null
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" -Name "WakeUp" -PropertyType DWord -Value 0 | Out-Null
}

Function DisableHomeGroups {
    Write-Output "Stopping and disabling Home Groups services..."
    If (Get-Service "HomeGroupListener" -ErrorAction SilentlyContinue) {
        Stop-Service "HomeGroupListener" -WarningAction SilentlyContinue
        Set-Service "HomeGroupListener" -StartupType Disabled
    }
    If (Get-Service "HomeGroupProvider" -ErrorAction SilentlyContinue) {
        Stop-Service "HomeGroupProvider" -WarningAction SilentlyContinue
        Set-Service "HomeGroupProvider" -StartupType Disabled
    }
}

Function DisableSharedExperiences {
    Write-Output "Disabling Shared Experiences..."
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP" | Out-Null
    }
    New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CDP" -Name "RomeSdkChannelUserAuthzPolicy" -PropertyType DWord -Value 0 | Out-Null
}

Function EnableClipboardHistory {
    Write-Output "Enabling Clipboard History..."
    New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Clipboard" -Name "EnableClipboardHistory" -PropertyType DWord -Value 1 | Out-Null
}

Function DisableRemoteAssistance {
    Write-Output "Disabling Remote Assistance..."
    New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -PropertyType DWord -Value 0 | Out-Null
}

Function EnableRemoteDesktop {
    Write-Output "Enabling Remote Desktop..."
    New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -PropertyType DWord -Value 0 | Out-Null
    Enable-NetFirewallRule -Name "RemoteDesktop*"
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
    Stop-Service "SysMain" -WarningAction SilentlyContinue
    Set-Service "SysMain" -StartupType Disabled
}

Function EnableHibernation {
    Write-Output "Enabling Hibernation..."
    New-ItemProperty -Force -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernateEnabled" -PropertyType DWord -Value 1 | Out-Null
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
    }
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -PropertyType DWord -Value 1 | Out-Null
    powercfg /HIBERNATE ON 2>&1 | Out-Null
}

Function EnableSleepTimeout {
    Write-Output "Enabling display and sleep mode timeouts..."
    powercfg /X monitor-timeout-ac 10
    powercfg /X monitor-timeout-dc 5
    powercfg /X standby-timeout-ac 30
    powercfg /X standby-timeout-dc 15
}

Function EnableFastStartup {
    Write-Output "Enabling Fast Startup..."
    New-ItemProperty -Force -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -PropertyType DWord -Value 1 | Out-Null
}

# # # # # # # # # # # #
# UI
# # # # # # # # # # # #
Function HideNetworkFromLockScreen {
    Write-Output "Hiding network options from Lock Screen..."
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "DontDisplayNetworkSelectionUI" -PropertyType DWord -Value 1 | Out-Null
}

Function ShowShutdownOnLockScreen {
    Write-Output "Showing shutdown options on Lock Screen..."
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ShutdownWithoutLogon" -PropertyType DWord -Value 1 | Out-Null
}

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

Function DisableFileDeleteConfirm {
    Write-Output "Disabling file delete confirmation dialog..."
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ConfirmFileDelete" -ErrorAction SilentlyContinue
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

Function UnpinStartMenuTiles {
    Write-Output "Unpinning all Start Menu tiles..."
    If ([System.Environment]::OSVersion.Version.Build -ge 15063 -And [System.Environment]::OSVersion.Version.Build -le 16299) {
        Get-ChildItem -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount" -Include "*.group" -Recurse | ForEach-Object {
            $data = (Get-ItemProperty -Path "$($_.PsPath)\Current" -Name "Data").Data -Join ","
            $data = $data.Substring(0, $data.IndexOf(",0,202,30") + 9) + ",0,202,80,0,0"
            Set-ItemProperty -Path "$($_.PsPath)\Current" -Name "Data" -Type Binary -Value $data.Split(",")
        }
    }
    ElseIf ([System.Environment]::OSVersion.Version.Build -ge 17134) {
        $key = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\*start.tilegrid`$windows.data.curatedtilecollection.tilecollection\Current"
        $data = $key.Data[0..25] + ([byte[]](202, 50, 0, 226, 44, 1, 1, 0, 0))
        Set-ItemProperty -Path $key.PSPath -Name "Data" -Type Binary -Value $data
        Stop-Process -Name "ShellExperienceHost" -Force -ErrorAction SilentlyContinue
    }
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

Function ShowEncCompFilesColor {
    Write-Output "Showing coloring of encrypted or compressed NTFS files..."
    New-ItemProperty -Force -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowEncryptCompressedColor" -PropertyType DWord -Value 1 | Out-Null
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
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}" -Recurse -ErrorAction SilentlyContinue
}

Function HideDownloadsFromThisPC {
    Write-Output "Hiding Downloads icon from This PC..."
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}" -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}" -Recurse -ErrorAction SilentlyContinue
}

Function HideDocumentsFromThisPC {
    Write-Output "Hiding Documents icon from This PC..."
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}" -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}" -Recurse -ErrorAction SilentlyContinue
}

Function HidePicturesFromThisPC {
    Write-Output "Hiding Pictures icon from This PC..."
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}" -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}" -Recurse -ErrorAction SilentlyContinue
}

Function HideVideosFromThisPC {
    Write-Output "Hiding Videos icon from This PC..."
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}" -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}" -Recurse -ErrorAction SilentlyContinue
}

Function HideMusicFromThisPC {
    Write-Output "Hiding Music icon from This PC..."
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}" -Recurse -ErrorAction SilentlyContinue
}

Function Hide3DObjectsFromThisPC {
    Write-Output "Hiding 3D Objects icon from This PC..."
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue
}

Function HideDocumentsFromExplorer {
    Write-Output "Hiding Documents icon from Explorer namespace..."
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" -Name "ThisPCPolicy" -PropertyType String -Value "Hide" | Out-Null
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{f42ee2d3-909f-4907-8871-4c22fc0bf756}\PropertyBag" -Name "ThisPCPolicy" -PropertyType String -Value "Hide" | Out-Null
}

Function HidePicturesFromExplorer {
    Write-Output "Hiding Pictures icon from Explorer namespace..."
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" -Name "ThisPCPolicy" -PropertyType String -Value "Hide" | Out-Null
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{0ddd015d-b06c-45d5-8c4c-f59713854639}\PropertyBag" -Name "ThisPCPolicy" -PropertyType String -Value "Hide" | Out-Null
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

Function Hide3DObjectsFromExplorer {
    Write-Output "Hiding 3D Objects icon from Explorer namespace..."
    If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Force | Out-Null
    }
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -PropertyType String -Value "Hide" | Out-Null
    If (!(Test-Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag")) {
        New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Force | Out-Null
    }
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}\PropertyBag" -Name "ThisPCPolicy" -PropertyType String -Value "Hide" | Out-Null
}

Function HideIncludeInLibraryMenu {
    Write-Output "Hiding 'Include in library' context menu item..."
    If (!(Test-Path "HKCR:")) {
        New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
    }
    Remove-Item -Path "HKCR:\Folder\ShellEx\ContextMenuHandlers\Library Location" -ErrorAction SilentlyContinue
}

Function HideGiveAccessToMenu {
    Write-Output "Hiding 'Give access to' context menu item..."
    If (!(Test-Path "HKCR:")) {
        New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
    }
    Remove-Item -LiteralPath "HKCR:\*\shellex\ContextMenuHandlers\Sharing" -ErrorAction SilentlyContinue
    Remove-Item -Path "HKCR:\Directory\Background\shellex\ContextMenuHandlers\Sharing" -ErrorAction SilentlyContinue
    Remove-Item -Path "HKCR:\Directory\shellex\ContextMenuHandlers\Sharing" -ErrorAction SilentlyContinue
    Remove-Item -Path "HKCR:\Drive\shellex\ContextMenuHandlers\Sharing" -ErrorAction SilentlyContinue
}

Function HideShareMenu {
    Write-Output "Hiding 'Share' context menu item..."
    If (!(Test-Path "HKCR:")) {
        New-PSDrive -Name "HKCR" -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" | Out-Null
    }
    Remove-Item -LiteralPath "HKCR:\*\shellex\ContextMenuHandlers\ModernSharing" -ErrorAction SilentlyContinue
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
    Stop-Process -Name "OneDrive" -Force -ErrorAction SilentlyContinue
    Start-Sleep -s 2
    $onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
    If (!(Test-Path $onedrive)) {
        $onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
    }
    Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
    Start-Sleep -s 2
    Stop-Process -Name "explorer" -Force -ErrorAction SilentlyContinue
    Start-Sleep -s 2
    Remove-Item -Path "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse -ErrorAction SilentlyContinue
    If (!(Test-Path "HKCR:")) {
        New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
    }
    Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
}

Function UninstallMsftBloat {
    Write-Output "Uninstalling default Microsoft applications..."
    Get-AppxPackage "Microsoft.3DBuilder" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.AppConnector" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.BingFinance" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.BingFoodAndDrink" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.BingHealthAndFitness" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.BingMaps" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.BingNews" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.BingSports" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.BingTranslator" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.BingTravel" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.BingWeather" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.CommsPhone" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.ConnectivityStore" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.FreshPaint" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.GetHelp" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.Getstarted" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.HelpAndTips" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.Media.PlayReadyClient.2" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.Messaging" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.Microsoft3DViewer" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.MicrosoftOfficeHub" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.MicrosoftPowerBIForWindows" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.MicrosoftSolitaireCollection" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.MicrosoftStickyNotes" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.MinecraftUWP" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.MixedReality.Portal" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.MoCamera" | Remove-AppxPackage
    # Get-AppxPackage "Microsoft.MSPaint" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.NetworkSpeedTest" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.OfficeLens" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.Office.OneNote" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.Office.Sway" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.OneConnect" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.People" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.Print3D" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.Reader" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.SkypeApp" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.Todos" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.Wallet" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.WebMediaExtensions" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.Whiteboard" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.WindowsAlarms" | Remove-AppxPackage
    # Get-AppxPackage "Microsoft.WindowsCamera" | Remove-AppxPackage
    Get-AppxPackage "microsoft.windowscommunicationsapps" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.WindowsFeedbackHub" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.WindowsMaps" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.WindowsPhone" | Remove-AppxPackage
    # Get-AppxPackage "Microsoft.Windows.Photos" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.WindowsReadingList" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.WindowsScan" | Remove-AppxPackage
    # Get-AppxPackage "Microsoft.WindowsSoundRecorder" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.WinJS.1.0" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.WinJS.2.0" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.YourPhone" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.ZuneMusic" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.ZuneVideo" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.ScreenSketch" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.Advertising.Xaml" | Remove-AppxPackage # Dependency for microsoft.windowscommunicationsapps, Microsoft.BingWeather
}

Function UninstallWindowsStore {
    Write-Output "Uninstalling Windows Store..."
    Get-AppxPackage "Microsoft.DesktopAppInstaller" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.Services.Store.Engagement" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.StorePurchaseApp" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.WindowsStore" | Remove-AppxPackage
}

function UninstallThirdPartyBloat {
    Write-Output "Uninstalling default third party applications..."
    Get-AppxPackage "2414FC7A.Viber" | Remove-AppxPackage
    Get-AppxPackage "41038Axilesoft.ACGMediaPlayer" | Remove-AppxPackage
    Get-AppxPackage "46928bounde.EclipseManager" | Remove-AppxPackage
    Get-AppxPackage "4DF9E0F8.Netflix" | Remove-AppxPackage
    Get-AppxPackage "64885BlueEdge.OneCalendar" | Remove-AppxPackage
    Get-AppxPackage "7EE7776C.LinkedInforWindows" | Remove-AppxPackage
    Get-AppxPackage "828B5831.HiddenCityMysteryofShadows" | Remove-AppxPackage
    Get-AppxPackage "89006A2E.AutodeskSketchBook" | Remove-AppxPackage
    Get-AppxPackage "9E2F88E3.Twitter" | Remove-AppxPackage
    Get-AppxPackage "A278AB0D.DisneyMagicKingdoms" | Remove-AppxPackage
    Get-AppxPackage "A278AB0D.DragonManiaLegends" | Remove-AppxPackage
    Get-AppxPackage "A278AB0D.MarchofEmpires" | Remove-AppxPackage
    Get-AppxPackage "ActiproSoftwareLLC.562882FEEB491" | Remove-AppxPackage
    Get-AppxPackage "AD2F1837.GettingStartedwithWindows8" | Remove-AppxPackage
    Get-AppxPackage "AD2F1837.HPJumpStart" | Remove-AppxPackage
    Get-AppxPackage "AD2F1837.HPRegistration" | Remove-AppxPackage
    Get-AppxPackage "AdobeSystemsIncorporated.AdobePhotoshopExpress" | Remove-AppxPackage
    Get-AppxPackage "Amazon.com.Amazon" | Remove-AppxPackage
    Get-AppxPackage "C27EB4BA.DropboxOEM" | Remove-AppxPackage
    Get-AppxPackage "CAF9E577.Plex" | Remove-AppxPackage
    Get-AppxPackage "CyberLinkCorp.hs.PowerMediaPlayer14forHPConsumerPC" | Remove-AppxPackage
    Get-AppxPackage "D52A8D61.FarmVille2CountryEscape" | Remove-AppxPackage
    Get-AppxPackage "D5EA27B7.Duolingo-LearnLanguagesforFree" | Remove-AppxPackage
    Get-AppxPackage "DB6EA5DB.CyberLinkMediaSuiteEssentials" | Remove-AppxPackage
    Get-AppxPackage "DolbyLaboratories.DolbyAccess" | Remove-AppxPackage
    Get-AppxPackage "Drawboard.DrawboardPDF" | Remove-AppxPackage
    Get-AppxPackage "E046963F.LenovoCompanion" | Remove-AppxPackage
    Get-AppxPackage "Facebook.Facebook" | Remove-AppxPackage
    Get-AppxPackage "Fitbit.FitbitCoach" | Remove-AppxPackage
    Get-AppxPackage "flaregamesGmbH.RoyalRevolt2" | Remove-AppxPackage
    Get-AppxPackage "GAMELOFTSA.Asphalt8Airborne" | Remove-AppxPackage
    Get-AppxPackage "KeeperSecurityInc.Keeper" | Remove-AppxPackage
    Get-AppxPackage "king.com.BubbleWitch3Saga" | Remove-AppxPackage
    Get-AppxPackage "king.com.CandyCrushFriends" | Remove-AppxPackage
    Get-AppxPackage "king.com.CandyCrushSaga" | Remove-AppxPackage
    Get-AppxPackage "king.com.CandyCrushSodaSaga" | Remove-AppxPackage
    Get-AppxPackage "LenovoCorporation.LenovoID" | Remove-AppxPackage
    Get-AppxPackage "LenovoCorporation.LenovoSettings" | Remove-AppxPackage
    Get-AppxPackage "Nordcurrent.CookingFever" | Remove-AppxPackage
    Get-AppxPackage "PandoraMediaInc.29680B314EFC2" | Remove-AppxPackage
    Get-AppxPackage "PricelinePartnerNetwork.Booking.comBigsavingsonhot" | Remove-AppxPackage
    Get-AppxPackage "SpotifyAB.SpotifyMusic" | Remove-AppxPackage
    Get-AppxPackage "ThumbmunkeysLtd.PhototasticCollage" | Remove-AppxPackage
    Get-AppxPackage "WinZipComputing.WinZipUniversal" | Remove-AppxPackage
    Get-AppxPackage "XINGAG.XING" | Remove-AppxPackage
}

Function DisableXboxFeatures {
    Write-Output "Disabling Xbox features..."
    Get-AppxPackage "Microsoft.XboxApp" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.XboxIdentityProvider" | Remove-AppxPackage -ErrorAction SilentlyContinue
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

Function DisableMediaSharing {
    Write-Output "Disabling media sharing..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Force | Out-Null
    }
    New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" -Name "PreventLibrarySharing" -PropertyType DWord -Value 1 | Out-Null
}

Function UninstallMediaPlayer {
    Write-Output "Uninstalling Windows Media Player..."
    Disable-WindowsOptionalFeature -Online -FeatureName "WindowsMediaPlayer" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

Function InstallPowerShellV2 {
    Write-Output "Installing PowerShell 2.0 Environment..."
    If ((Get-CimInstance -Class "Win32_OperatingSystem").ProductType -eq 1) {
        Enable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" -NoRestart -WarningAction SilentlyContinue | Out-Null
    }
    Else {
        Install-WindowsFeature -Name "PowerShell-V2" -WarningAction SilentlyContinue | Out-Null
    }
}

Function InstallLinuxSubsystem {
    Write-Output "Installing Linux Subsystem..."
    If ([System.Environment]::OSVersion.Version.Build -eq 14393) {
        # 1607 needs developer mode to be enabled
        New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowDevelopmentWithoutDevLicense" -PropertyType DWord -Value 1 | Out-Null
        New-ItemProperty -Force -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" -Name "AllowAllTrustedApps" -PropertyType DWord -Value 1 | Out-Null
    }
    Enable-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-Subsystem-Linux" -NoRestart -WarningAction SilentlyContinue | Out-Null
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

Function RemovePhotoViewerOpenWith {
    Write-Output "Removing Photo Viewer from 'Open with...'"
    If (!(Test-Path "HKCR:")) {
        New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
    }
    Remove-Item -Path "HKCR:\Applications\photoviewer.dll\shell\open" -Recurse -ErrorAction SilentlyContinue
}

Function RemoveFaxPrinter {
    Write-Output "Removing Default Fax Printer..."
    Remove-Printer -Name "Fax" -ErrorAction SilentlyContinue
}

Function UninstallFaxAndScan {
    Write-Output "Uninstalling Windows Fax and Scan Services..."
    Disable-WindowsOptionalFeature -Online -FeatureName "FaxServicesClientPackage" -NoRestart -WarningAction SilentlyContinue | Out-Null
}

# # # # # # # # # # # #
# Custom
# # # # # # # # # # # #
function MorePrivacyTweaks {
    Write-Output "Running more privacy tweaks..."
    New-ItemProperty -Force -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost' -name EnableWebContentEvaluation -PropertyType DWord -Value 0 | Out-Null
    New-ItemProperty -Force -path 'HKCU:\Software\Microsoft\Input\IPC' -name Enabled -PropertyType DWord -Value 0 -ErrorAction SilentlyContinue | Out-Null
}

function InstallChocolatey {
    Write-Output "Installing Chocolatey..."
    Set-ExecutionPolicy Bypass -Scope Process -Force; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    choco feature enable -n=allowGlobalConfirmation
}

function InstallChocoPackages {
    Write-Output "Installing Choco packages..."
    # windows
    choco install vcredist140 vcredist2008 vcredist2010 vcredist2012 vcredist2013 vcredist2015
    # vital
    choco install notepadplusplus microsoft-windows-terminal powershell-core 7zip chromium firefox ccleaner vlc
    # tweaking
    choco install shutup10
    # image editing
    choco install greenshot
    # development
    choco install git
}

function CleanContextMenu {
    Write-Output "Cleaning up context menu..."
    Remove-Item -path "Registry::HKCR\.bmp\ShellNew" -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -path "Registry::HKCR\.contact\ShellNew" -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -path "Registry::HKCR\.zip\ShellNew" -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -path "Registry::HKCR\.rar\ShellNew" -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -path "Registry::HKCR\Folder\shellex\ContextMenuHandlers\PintoStartScreen" -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -path "Registry::HKCR\AllFilesystemObjects\shellex\ContextMenuHandlers\{596AB062-B4D2-4215-9F74-E9109B0A8153}" -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -literalpath "Registry::HKCR\*\shellex\ContextMenuHandlers\{90AA3A4E-1CBA-4233-B8BB-535773D48449}" -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -literalpath "Registry::HKCR\*\shellex\ContextMenuHandlers\{a2a9545d-a0c2-42b4-9708-a0b2badd77c8}" -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -literalpath "Registry::HKCR\*\shellex\ContextMenuHandlers\PDFCreator.ShellContextMenu" -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -literalpath "Registry::HKCR\*\shellex\ContextMenuHandlers\SimpleShlExt" -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -path "Registry::HKCR\Directory\shell\AddToPlaylistVLC" -Recurse -ErrorAction SilentlyContinue | Out-Null
    Remove-Item -path "Registry::HKCR\Directory\shell\PlayWithVLC" -Recurse -ErrorAction SilentlyContinue | Out-Null
}

function CleanStartup {
    Write-Output "Cleaning up startup programs..."
    Remove-ItemProperty -path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name "CCleaner Smart Cleaning" -ErrorAction SilentlyContinue
}

function CleanDirectories {
    Write-Output "Cleaning up user directories..."
    Get-ChildItem -Path "$env:USERPROFILE\Desktop" -Include * -Recurse | ForEach-Object { $_.Delete() }
    Get-ChildItem -Path "$env:USERPROFILE\Documents" -Include * -Recurse | ForEach-Object { $_.Delete() }
    Remove-Item -Path "$env:USERPROFILE\Pictures" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:USERPROFILE\Videos" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:USERPROFILE\Music" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:USERPROFILE\Favorites" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:USERPROFILE\Links" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:USERPROFILE\contacts" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "$env:USERPROFILE\3D Objects" -Force -Recurse -ErrorAction SilentlyContinue
    # Get-ChildItem -Force -Path "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Start Menu" -Include * -Recurse | ForEach-Object { Remove-Item $_.FullName -Force -Recurse }
    # Get-ChildItem -Force -Path "$env:PROGRAMDATA\Microsoft\Windows\Start Menu" -Include * -Recurse | ForEach-Object { Remove-Item $_.FullName -Force -Recurse }
    Remove-Item -Path "C:\NVIDIA" -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item -Path "C:\AMD" -Force -Recurse -ErrorAction SilentlyContinue
}

Function CopyFiles {
    Write-Output "Copying files to C: ..."
    Copy-Item ".\user\*" -Destination "$env:USERPROFILE\" -Recurse -Force
    Copy-Item ".\Program Files\*" -Destination "$env:PROGRAMFILES\" -Recurse -Force
}

function SetBackground {
    Write-Output "Setting background..."
    New-ItemProperty -Force -path 'HKCU:\Control Panel\Desktop' -name Wallpaper -value "$env:USERPROFILE\background.bmp" | Out-Null
    rundll32.exe user32.dll, UpdatePerUserSystemParameters 1, True
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

function Shutup10 {
    Write-Output "Running Shutup10..."
    Start-Process -FilePath "$env:PROGRAMDATA\chocolatey\bin\OOSU10.exe" -ArgumentList "ooshutup10.cfg /quiet" -NoNewWindow -Wait
    Start-Sleep -s 5
    # TODO at the end
    Remove-Item -Path "OOSU10.ini" -ErrorAction SilentlyContinue
}

function InstallPsCorePackages {
    Write-Output "Installing PS Core packages..."
    Install-Module posh-git -Force
    Install-Module oh-my-posh -Force
}

function InstallExes {
    Write-Output "Installing EXEs..."
    Start-Process setup\acrobatxi.exe -Wait
    Start-Process setup\luxtrust.exe -Wait
    Start-Process setup\messagesave.exe -Wait
    Start-Process setup\simplytag.exe -Wait
    Start-Process setup\office\setup.exe -Wait
    Start-Process setup\Delugia.Nerd.Font.Complete.ttf -Wait
}

function OpenManualWindows {
    control /name Microsoft.IndexingOptions
    Start-Process -FilePath "C:\Program Files\Chromium\Application\chrome.exe"
    control /name Microsoft.DevicesAndPrinters
}

$tweaks | ForEach-Object { Invoke-Expression $_ }