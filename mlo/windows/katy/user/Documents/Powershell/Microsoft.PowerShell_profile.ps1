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

# Chrome
function g { Start-Process -FilePath "C:\Program Files\Chromium\Application\chrome.exe" -ArgumentList "https://www.google.com/search?q=$args" }

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
function downloads { e D:\Downloads }

Import-Module posh-git
Import-Module oh-my-posh
Set-Theme Agnoster