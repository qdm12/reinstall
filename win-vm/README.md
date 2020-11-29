# Windows gaming VM reinstall

Setup Windows 10 Virtual machine for gaming.

## Pre-requisites

1. [Install the Windows 10 VM](https://github.com/qdm12/VFIO-Arch-Guide)
1. Install Windows updates
1. Reboot

## Run the script

Right click on script.ps1 and select Run with Powershell

## More steps

## TODOs

- Install Windows updates and continue on reboot

### Redo before reinstall

- Save games
- Update files of desktop
- Update files of desktop
- Export Taskband:

    ```powershell
    reg export HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband taskband.reg
    ```

- Export File extensions:

    ```powershell
    reg export HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts fileexts.reg
    ```
