<#
.SYNOPSIS
    Skrip Audit & Remediasi Keamanan Windows 10/11 (CIS Benchmark Aligned - 24 Controls).
.DESCRIPTION
    Menggabungkan seluruh modul audit dan remediasi otomatis untuk parameter keamanan 
    sistem operasi Windows 10/11 secara menyeluruh.
.PARAMETER Fix
    Jika switch ini dipanggil, skrip akan langsung memperbaiki seluruh temuan NON-COMPLIANT.
.EXAMPLE
    .\Sentinel.ps1
    (Mode Audit Only)
.EXAMPLE
    .\Sentinel.ps1 -Fix
    (Mode Audit & Remediasi Otomatis)
#>

[CmdletBinding()]
param (
    [switch]$Fix
)

# Memastikan eksekusi berjalan sebagai Administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Harap jalankan skrip ini menggunakan PowerShell (Run as Administrator)!"
    exit
}

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "           SKRIP AUDIT & REMEDIASI KEAMANAN WINDOWS 10/11             " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
if ($Fix) {
    Write-Host "[!] Mode: AUDIT & REMEDIASI OTOMATIS DIAKTIFKAN" -ForegroundColor Yellow
} else {
    Write-Host "[*] Mode: AUDIT ONLY (Gunakan parameter -Fix untuk perbaikan)" -ForegroundColor Green
}
Write-Host "----------------------------------------------------------------------`n"

# ----------------------------------------------------------------------
# HELPER FUNCTIONS
# ----------------------------------------------------------------------
function Set-RegValue {
    param (
        [string]$Path,
        [string]$Name,
        [PSObject]$Value,
        [string]$PropertyType = "DWord"
    )
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $PropertyType -Force
}

function Log-Result {
    param (
        [string]$ControlID,
        [string]$Description,
        [string]$Status,
        [string]$Detail
    )
    $color = if ($Status -eq "COMPLIANT") { "Green" } elseif ($Status -eq "NON-COMPLIANT") { "Red" } else { "Yellow" }
    Write-Host "[$ControlID] $Description" -NoNewline
    Write-Host " -> $Status" -ForegroundColor $color
    if ($Detail) { Write-Host "    Detail: $Detail" -ForegroundColor Gray }
}

# ----------------------------------------------------------------------
# 1. ACCOUNT POLICIES & LOCKOUT (KONTROL 1.1 & 1.2)
# ----------------------------------------------------------------------
Write-Host "[+] Checking Section 1: Account Policies..." -ForegroundColor Yellow

if ($Fix) {
    net accounts /minpwlen:14 /maxpwage:365 /minpwage:1 /uniquepw:24 | Out-Null
    net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15 | Out-Null
}

$netAccounts = net accounts
$minPw = ($netAccounts | Select-String "Minimum password length").ToString().Split(":")[-1].Trim()
$lockout = ($netAccounts | Select-String "Lockout threshold").ToString().Split(":")[-1].Trim()

if ([int]$minPw -ge 14) { Log-Result "1.1" "Minimum Password Length (>=14)" "COMPLIANT" "Current: $minPw" } 
else { Log-Result "1.1" "Minimum Password Length (>=14)" "NON-COMPLIANT" "Current: $minPw" }

if ($lockout -ne "Never" -and [int]$lockout -le 5 -and [int]$lockout -gt 0) { Log-Result "1.2" "Account Lockout Threshold (<=5)" "COMPLIANT" "Current: $lockout" } 
else { Log-Result "1.2" "Account Lockout Threshold (<=5)" "NON-COMPLIANT" "Current: $lockout" }

$regLsa = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
if ($Fix) {
    Set-RegValue -Path $regLsa -Name "ComplexityEnabled" -Value 1
    Set-RegValue -Path $regLsa -Name "ReversibleEncryptionEnabled" -Value 0
}
$complexity = (Get-ItemProperty -Path $regLsa -Name "ComplexityEnabled" -ErrorAction SilentlyContinue).ComplexityEnabled
$reversible = (Get-ItemProperty -Path $regLsa -Name "ReversibleEncryptionEnabled" -ErrorAction SilentlyContinue).ReversibleEncryptionEnabled

if ($complexity -eq 1) { Log-Result "1.1.1" "Password Complexity Enabled" "COMPLIANT" } else { Log-Result "1.1.1" "Password Complexity Enabled" "NON-COMPLIANT" }
if ($reversible -eq 0) { Log-Result "1.1.2" "Reversible Encryption Disabled" "COMPLIANT" } else { Log-Result "1.1.2" "Reversible Encryption Disabled" "NON-COMPLIANT" }

# ----------------------------------------------------------------------
# 2. LOCAL POLICIES & AUDIT POLICY (KONTROL 2.1 & 2.2)
# ----------------------------------------------------------------------
Write-Host "`n[+] Checking Section 2: Local Accounts & Audit Configuration..." -ForegroundColor Yellow

$guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
$adminLocal = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue

if ($Fix) {
    if ($guest.Enabled) { Disable-LocalUser -Name "Guest" }
    if ($adminLocal.Enabled) { Disable-LocalUser -Name "Administrator" }
}

$guestState = (Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue).Enabled
$adminState = (Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue).Enabled

if (-not $guestState) { Log-Result "2.1.1" "Built-in Guest Account Disabled" "COMPLIANT" } else { Log-Result "2.1.1" "Built-in Guest Account Disabled" "NON-COMPLIANT" }
if (-not $adminState) { Log-Result "2.1.2" "Built-in Administrator Account Disabled" "COMPLIANT" } else { Log-Result "2.1.2" "Built-in Administrator Account Disabled" "NON-COMPLIANT" }

if ($Fix) {
    Set-RegValue -Path $regLsa -Name "SCENoApplyLegacyAuditPolicy" -Value 1
    auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Logon" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Sensitive Privilege Use" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable | Out-Null
    auditpol /set /subcategory:"Process Creation" /success:enable /failure:disable | Out-Null
}

$sceVal = (Get-ItemProperty -Path $regLsa -Name "SCENoApplyLegacyAuditPolicy" -ErrorAction SilentlyContinue).SCENoApplyLegacyAuditPolicy
if ($sceVal -eq 1) { Log-Result "2.2" "Force Advanced Audit Policy Enforcement" "COMPLIANT" } else { Log-Result "2.2" "Force Advanced Audit Policy Enforcement" "NON-COMPLIANT" }

# ----------------------------------------------------------------------
# 3. SECURITY OPTIONS (KONTROL 3.1 - 3.4)
# ----------------------------------------------------------------------
Write-Host "`n[+] Checking Section 3: Security Options & Auth Settings..." -ForegroundColor Yellow

$sysPolicies = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$msvPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"

if ($Fix) {
    Set-RegValue -Path $regLsa -Name "LmCompatibilityLevel" -Value 5
    Set-RegValue -Path $regLsa -Name "RestrictAnonymousSAM" -Value 1
    Set-RegValue -Path $regLsa -Name "RestrictNullSessAccess" -Value 1
    Set-RegValue -Path $sysPolicies -Name "InactivityTimeoutSecs" -Value 900
    Set-RegValue -Path $msvPath -Name "NTLMMinClientSec" -Value 537395200 # 0x20080000
}

$lmLevel = (Get-ItemProperty -Path $regLsa -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue).LmCompatibilityLevel
$restrictSam = (Get-ItemProperty -Path $regLsa -Name "RestrictAnonymousSAM" -ErrorAction SilentlyContinue).RestrictAnonymousSAM
$inactivity = (Get-ItemProperty -Path $sysPolicies -Name "InactivityTimeoutSecs" -ErrorAction SilentlyContinue).InactivityTimeoutSecs
$ntlmMin = (Get-ItemProperty -Path $msvPath -Name "NTLMMinClientSec" -ErrorAction SilentlyContinue).NTLMMinClientSec

if ($lmLevel -eq 5) { Log-Result "3.1" "LAN Manager Auth Level (Send NTLMv2 only)" "COMPLIANT" } else { Log-Result "3.1" "LAN Manager Auth Level" "NON-COMPLIANT" "Current: $lmLevel" }
if ($restrictSam -eq 1) { Log-Result "3.2" "Restrict Anonymous Access to SAM" "COMPLIANT" } else { Log-Result "3.2" "Restrict Anonymous Access to SAM" "NON-COMPLIANT" }
if ($inactivity -and $inactivity -le 900 -and $inactivity -gt 0) { Log-Result "3.3" "Inactivity Timeout (<=900s)" "COMPLIANT" "Current: $inactivity Secs" } else { Log-Result "3.3" "Inactivity Timeout" "NON-COMPLIANT" }
if ($ntlmMin -eq 537395200) { Log-Result "3.4" "NTLM Min Client Security (NTLMv2 NTLM2)" "COMPLIANT" } else { Log-Result "3.4" "NTLM Min Client Security" "NON-COMPLIANT" }

# ----------------------------------------------------------------------
# 4. WINDOWS FIREWALL WITH ADVANCED SECURITY (KONTROL 4.1)
# ----------------------------------------------------------------------
Write-Host "`n[+] Checking Section 4: Windows Firewall Configurations..." -ForegroundColor Yellow

if ($Fix) {
    Set-NetFirewallProfile -Name Domain,Private,Public -Enabled True -DefaultInboundAction Block -LogBlocked True -LogMaxSizeKilobytes 16384 | Out-Null
    Set-NetFirewallProfile -Name Domain -NotifyOnListen False | Out-Null
}

foreach ($p in ("Domain", "Private", "Public")) {
    $fw = Get-NetFirewallProfile -Name $p
    if ($fw.Enabled -eq $true -and $fw.DefaultInboundAction -eq "Block" -and $fw.LogBlocked -eq $true) {
        Log-Result "4.1" "Firewall Profile: $p" "COMPLIANT" "Enabled: True, Inbound: Block, LogBlocked: True"
    } else {
        Log-Result "4.1" "Firewall Profile: $p" "NON-COMPLIANT"
    }
}

# ----------------------------------------------------------------------
# 5. EVENT LOG CONFIGURATION (KONTROL 5.1 - 5.3)
# ----------------------------------------------------------------------
Write-Host "`n[+] Checking Section 5: Event Log Configurations..." -ForegroundColor Yellow

$logs = @(
    @{ Name = "Application"; MinSize = 33554432 },
    @{ Name = "Security";    MinSize = 201326592 },
    @{ Name = "System";      MinSize = 33554432 }
)

foreach ($l in $logs) {
    $logObj = Get-WinEvent -ListLog $l.Name
    if ($Fix -and $logObj.MaximumSizeInBytes -lt $l.MinSize) {
        wevtutil sl $l.Name /ms:$($l.MinSize)
        $logObj = Get-WinEvent -ListLog $l.Name
    }
    
    if ($logObj.MaximumSizeInBytes -ge $l.MinSize) {
        Log-Result "5.0" "Event Log Size: $($l.Name)" "COMPLIANT" "Current: $([math]::Round($logObj.MaximumSizeInBytes/1MB)) MB"
    } else {
        Log-Result "5.0" "Event Log Size: $($l.Name)" "NON-COMPLIANT" "Current: $([math]::Round($logObj.MaximumSizeInBytes/1MB)) MB"
    }
}

# ----------------------------------------------------------------------
# 6. CREDENTIAL PROTECTION & BITLOCKER (KONTROL 6.1 & 6.2)
# ----------------------------------------------------------------------
Write-Host "`n[+] Checking Section 6: LSASS & BitLocker Encryption..." -ForegroundColor Yellow

$wdigestPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
if ($Fix) {
    Set-RegValue -Path $wdigestPath -Name "UseLogonCredential" -Value 0
    Set-RegValue -Path $regLsa -Name "RunAsPPL" -Value 1
}

$wdigest = (Get-ItemProperty -Path $wdigestPath -Name "UseLogonCredential" -ErrorAction SilentlyContinue).UseLogonCredential
$ppl = (Get-ItemProperty -Path $regLsa -Name "RunAsPPL" -ErrorAction SilentlyContinue).RunAsPPL

if ($wdigest -eq 0) { Log-Result "6.1.1" "WDigest Auth Disabled" "COMPLIANT" } else { Log-Result "6.1.1" "WDigest Auth Disabled" "NON-COMPLIANT" }
if ($ppl -eq 1) { Log-Result "6.1.2" "LSASS RunAsPPL Protection" "COMPLIANT" } else { Log-Result "6.1.2" "LSASS RunAsPPL Protection" "NON-COMPLIANT" }

# BitLocker Audit
$bitlocker = Get-BitLockerVolume -MountPoint "C:" -ErrorAction SilentlyContinue
if ($bitlocker.ProtectionStatus -eq "On") {
    Log-Result "6.2" "BitLocker C: Encryption Status" "COMPLIANT" "Status: On ($($bitlocker.VolumeStatus))"
} else {
    Log-Result "6.2" "BitLocker C: Encryption Status" "NON-COMPLIANT" "Protection Off (Membutuhkan Konfigurasi Manual)"
}

# ----------------------------------------------------------------------
# 7. SYSTEM SERVICES (KONTROL 7.1 & 7.2)
# ----------------------------------------------------------------------
Write-Host "`n[+] Checking Section 7: System Services Hardening..." -ForegroundColor Yellow

# 7.1 Disabled Services
$unsecureServices = @("RemoteRegistry", "RemoteAccess", "SSDPSRV", "upnphost", "XblAuthManager", "WMPNetworkSvc", "Spooler")
foreach ($svc in $unsecureServices) {
    $serviceObj = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($serviceObj) {
        if ($Fix -and $serviceObj.StartType -ne "Disabled") {
            Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
            Set-Service -Name $svc -StartupType Disabled
            $serviceObj = Get-Service -Name $svc
        }
        if ($serviceObj.StartType -eq "Disabled") { Log-Result "7.1" "Service $svc Disabled" "COMPLIANT" } 
        else { Log-Result "7.1" "Service $svc Disabled" "NON-COMPLIANT" "Current: $($serviceObj.StartType)" }
    }
}

# 7.2 Required Services Running
$requiredServices = @("WinDefend", "MpsSvc", "EventLog", "CryptSvc")
foreach ($rSvc in $requiredServices) {
    $rObj = Get-Service -Name $rSvc -ErrorAction SilentlyContinue
    if ($rObj) {
        if ($Fix -and $rObj.Status -ne "Running") {
            Set-Service -Name $rSvc -StartupType Automatic
            Start-Service -Name $rSvc -ErrorAction SilentlyContinue
            $rObj = Get-Service -Name $rSvc
        }
        if ($rObj.Status -eq "Running") { Log-Result "7.2" "Required Service Running: $rSvc" "COMPLIANT" } 
        else { Log-Result "7.2" "Required Service Running: $rSvc" "NON-COMPLIANT" "Current: $($rObj.Status)" }
    }
}

# ----------------------------------------------------------------------
# 8. USER ACCOUNT CONTROL / UAC (KONTROL 8.1 - 8.4)
# ----------------------------------------------------------------------
Write-Host "`n[+] Checking Section 8: User Account Control (UAC)..." -ForegroundColor Yellow

if ($Fix) {
    Set-RegValue -Path $sysPolicies -Name "EnableLUA" -Value 1
    Set-RegValue -Path $sysPolicies -Name "ConsentPromptBehaviorAdmin" -Value 2
    Set-RegValue -Path $sysPolicies -Name "ConsentPromptBehaviorUser" -Value 0
    Set-RegValue -Path $sysPolicies -Name "PromptOnSecureDesktop" -Value 1
}

$lua = (Get-ItemProperty -Path $sysPolicies -Name "EnableLUA" -ErrorAction SilentlyContinue).EnableLUA
$promptAdmin = (Get-ItemProperty -Path $sysPolicies -Name "ConsentPromptBehaviorAdmin" -ErrorAction SilentlyContinue).ConsentPromptBehaviorAdmin
$promptUser = (Get-ItemProperty -Path $sysPolicies -Name "ConsentPromptBehaviorUser" -ErrorAction SilentlyContinue).ConsentPromptBehaviorUser
$secureDesktop = (Get-ItemProperty -Path $sysPolicies -Name "PromptOnSecureDesktop" -ErrorAction SilentlyContinue).PromptOnSecureDesktop

if ($lua -eq 1) { Log-Result "8.1" "UAC EnableLUA" "COMPLIANT" } else { Log-Result "8.1" "UAC EnableLUA" "NON-COMPLIANT" }
if ($promptAdmin -ge 2) { Log-Result "8.2" "UAC Admin Prompt Configuration" "COMPLIANT" } else { Log-Result "8.2" "UAC Admin Prompt Configuration" "NON-COMPLIANT" }
if ($promptUser -eq 0) { Log-Result "8.3" "UAC Standard User Prompt (Automatically Deny)" "COMPLIANT" } else { Log-Result "8.3" "UAC Standard User Prompt" "NON-COMPLIANT" }
if ($secureDesktop -eq 1) { Log-Result "8.4" "UAC Secure Desktop Enabled" "COMPLIANT" } else { Log-Result "8.4" "UAC Secure Desktop Enabled" "NON-COMPLIANT" }

# ----------------------------------------------------------------------
# 9. PENGATURAN REGISTRY TAMBAHAN / MSS (KONTROL 9.1 - 9.6)
# ----------------------------------------------------------------------
Write-Host "`n[+] Checking Section 9: MSS & Network Hardening Registry..." -ForegroundColor Yellow

$winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$tcpipPath    = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
$tcpip6Path   = "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"
$netbtPath    = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"
$sessionPath  = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager"

if ($Fix) {
    Set-RegValue -Path $winlogonPath -Name "AutoAdminLogon" -Value "0" -PropertyType "String"
    Set-RegValue -Path $tcpipPath -Name "DisableIPSourceRouting" -Value 2
    Set-RegValue -Path $tcpip6Path -Name "DisableIPSourceRouting" -Value 2
    Set-RegValue -Path $tcpipPath -Name "EnableICMPRedirect" -Value 0
    Set-RegValue -Path $netbtPath -Name "NoNameReleaseOnDemand" -Value 1
    Set-RegValue -Path $tcpipPath -Name "PerformRouterDiscovery" -Value 0
    Set-RegValue -Path $sessionPath -Name "SafeDllSearchMode" -Value 1
}

$autoLogon = (Get-ItemProperty -Path $winlogonPath -Name "AutoAdminLogon" -ErrorAction SilentlyContinue).AutoAdminLogon
$ipRoute = (Get-ItemProperty -Path $tcpipPath -Name "DisableIPSourceRouting" -ErrorAction SilentlyContinue).DisableIPSourceRouting
$icmpRedir = (Get-ItemProperty -Path $tcpipPath -Name "EnableICMPRedirect" -ErrorAction SilentlyContinue).EnableICMPRedirect
$safeDll = (Get-ItemProperty -Path $sessionPath -Name "SafeDllSearchMode" -ErrorAction SilentlyContinue).SafeDllSearchMode

if ($autoLogon -eq "0") { Log-Result "9.1" "AutoAdminLogon Disabled" "COMPLIANT" } else { Log-Result "9.1" "AutoAdminLogon Disabled" "NON-COMPLIANT" }
if ($ipRoute -eq 2) { Log-Result "9.2" "Disable IP Source Routing" "COMPLIANT" } else { Log-Result "9.2" "Disable IP Source Routing" "NON-COMPLIANT" }
if ($icmpRedir -eq 0) { Log-Result "9.3" "Disable ICMP Redirects" "COMPLIANT" } else { Log-Result "9.3" "Disable ICMP Redirects" "NON-COMPLIANT" }
if ($safeDll -eq 1) { Log-Result "9.4" "Safe DLL Search Mode Enabled" "COMPLIANT" } else { Log-Result "9.4" "Safe DLL Search Mode Enabled" "NON-COMPLIANT" }

# ----------------------------------------------------------------------
# 10. REMOTE DESKTOP & POWERSHELL LOGGING (KONTROL 10.1 & 10.2)
# ----------------------------------------------------------------------
Write-Host "`n[+] Checking Section 10: RDP Security & PowerShell Logging..." -ForegroundColor Yellow

$rdpWinPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
$rdpTsPath  = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
$psLogPath  = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"

if ($Fix) {
    Set-RegValue -Path $rdpWinPath -Name "UserAuthentication" -Value 1
    Set-RegValue -Path $rdpWinPath -Name "MinEncryptionLevel" -Value 3
    Set-RegValue -Path $rdpTsPath  -Name "fDisableCdm" -Value 1
    Set-RegValue -Path $psLogPath  -Name "EnableScriptBlockLogging" -Value 1
}

$rdpNla = (Get-ItemProperty -Path $rdpWinPath -Name "UserAuthentication" -ErrorAction SilentlyContinue).UserAuthentication
$rdpEnc = (Get-ItemProperty -Path $rdpWinPath -Name "MinEncryptionLevel" -ErrorAction SilentlyContinue).MinEncryptionLevel
$rdpDrive = (Get-ItemProperty -Path $rdpTsPath -Name "fDisableCdm" -ErrorAction SilentlyContinue).fDisableCdm
$psLog = (Get-ItemProperty -Path $psLogPath -Name "EnableScriptBlockLogging" -ErrorAction SilentlyContinue).EnableScriptBlockLogging

if ($rdpNla -eq 1) { Log-Result "10.1.1" "RDP Require NLA Authentication" "COMPLIANT" } else { Log-Result "10.1.1" "RDP Require NLA Authentication" "NON-COMPLIANT" }
if ($rdpEnc -ge 3) { Log-Result "10.1.2" "RDP Encryption Level (High)" "COMPLIANT" } else { Log-Result "10.1.2" "RDP Encryption Level (High)" "NON-COMPLIANT" }
if ($rdpDrive -eq 1) { Log-Result "10.1.3" "RDP Drive Redirection Disabled" "COMPLIANT" } else { Log-Result "10.1.3" "RDP Drive Redirection Disabled" "NON-COMPLIANT" }
if ($psLog -eq 1) { Log-Result "10.2" "PowerShell Script Block Logging Enabled" "COMPLIANT" } else { Log-Result "10.2" "PowerShell Script Block Logging Enabled" "NON-COMPLIANT" }

Write-Host "`n======================================================================" -ForegroundColor Cyan
Write-Host "                     AUDIT SELESAI DILAKUKAN                          " -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
