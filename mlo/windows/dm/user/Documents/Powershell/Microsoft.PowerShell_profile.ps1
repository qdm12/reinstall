function admin {
    Start-Process pwsh -Verb runAs
}
function npp {
    if (!$args) {
        Start-Process -FilePath "C:\Program Files\Notepad++\notepad++.exe"
        return
    }
    Start-Process -FilePath "C:\Program Files\Notepad++\notepad++.exe" -ArgumentList $args
}
function his {
    code "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
}
function a { npp "$PROFILE" }
Set-Alias -Name "clear" -Value "cls" -Option AllScope
# Set-Alias -Name "ls" -Value "ls --show-control-chars -F --color" -Option AllScope
function ip { Get-NetAdapter Ethernet | Get-NetIPAddress  -AddressFamily IPv4 | Select-Object IPAddress | Write-Host -NoNewline }
function backupphone { adb backup -system -apk -shared -all -f backup.ab }
function restorephone { adb restore backup.ab }
function ydl { youtube-dl --extract-audio --audio-format mp3 $args }

# Chrome
function g { Start-Process -FilePath "C:\Program Files\Chromium\Application\chrome.exe" -ArgumentList "https://www.google.com/search?q=$args" }

# SSH
function sshconfig { npp $env:USERPROFILE/.ssh/config }
function sshterra { ssh dm@terra }
function sshterrae { ssh dm@terrae }
function sshasterisk { ssh root@asterisk }
function sshsophos { ssh admin@192.168.67.1 }

# Explorer
function e {
    if (!$args) {
        explorer .
        return
    }
    explorer "$args"
}
function user { e $env:USERPROFILE }
function desktop { e $env:USERPROFILE\Desktop }
function downloads { e $env:USERPROFILE\Downloads }

Import-Module posh-git
Import-Module oh-my-posh
Set-Theme Agnoster