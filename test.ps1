# Task 1: Disable anonymous enumeration of SAM accounts and shares
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RestrictNullSessAccess" -Value 1

# Task 2: Disable the Guest account
Set-LocalUser -Name "Guest" -Enabled $false

# Task 3: Ensure a secure account lockout duration exists
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "LockoutDuration" -Value 30

# Task 4: Limit local use of blank passwords to console only
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LimitBlankPasswordUse" -Value 1

# Task 5: Enable the Windows Update Service
Set-Service -Name "wuauserv" -StartupType "Automatic"
Start-Service -Name "wuauserv"

# Task 6: Disable the Microsoft FTP Service
Set-Service -Name "ftpsvc" -Status "Stopped"
Set-Service -Name "ftpsvc" -StartupType "Disabled"
