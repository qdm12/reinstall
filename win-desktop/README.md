# Windows Desktop reinstall

Setup Windows 10 with tweaks, configurations and Docker everything.

## Pre-requisites

1. Install W10 from a USB drive in UEFI/GPT mode
1. Install Windows updates
1. Verify partitions (one for Docker sharing) and drive letters
1. Install all drivers (Nvidia too)
1. Reboot

## Run the script

Right click on script.ps1 and select Run with Powershell

## More steps

- Login to Chromium and set Chromium as default browser
- Indexing locations (open indexing window)
    - `C:\%USERPFORFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs`
    - `C:\ProgramData\chocolatey\bin`
- Winrar Context menu
- Login and configuration of Docker Desktop
- [MakeMKV key](https://makemkv.com/forum/viewtopic.php?f=5&t=1053)
- Setup bluetooth devices
    - Headset
    - Earset
    - Keyboard
    - Mouse
- Setup Wifi devices
    - Canon selphy
    - Xbox Controller

## TODOs

- Display end message with manual steps to do

### Redo before reinstall

- Shadowsocks config export
- Wireguard config export
- Redo taskband.reg
- Update files of desktop, start menu

### Sometime

- Wincreds
    - Docker
    - Samba
- Hashcat
- Docker in Arch WSL 2 (when released)
- Periodic `choco install malwarebytes --force`
- Install Windows updates and continue on reboot
- Windows remote desktop connection
- Regenerate seed/derivatex with prompt