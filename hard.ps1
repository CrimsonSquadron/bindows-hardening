(Get-WmiObject -Query "SELECT * FROM Win32_UserAccount WHERE Name='Guest'").Disabled = $true

Get-Service -Name "Microsoft FTP Service"

Stop-Service -Name "Microsoft FTP Service"

Set-Service -Name "Microsoft FTP Service" -StartupType Disabled

Get-Service -Name "Microsoft FTP Service"

Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LockoutBadCount" -Value 5
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LockoutDuration" -Value 1200

Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "MaxPasswordAge" -Value 90
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "MinPasswordAge" -Value 10
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "MinimumPasswordLength" -Value 4
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PasswordComplexity" -Value 1

gpupdate /force


