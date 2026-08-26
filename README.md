<div align="center">

# :shield:Sentinel
### [Audit & Remediasi Keamanan Otomatis Windows 10/11]

</div>

<p align="center">
  <a href="https://microsoft.com"><img src="https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011-0078D6.svg" alt="Platform"></a>
  <a href="https://docs.microsoft.com/powershell/"><img src="https://img.shields.io/badge/PowerShell-v5.1%2B-blue.svg" alt="PowerShell"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-orange.svg" alt="License: MIT"></a>
</p>

---

# Abstrak Teknis

*Sentinel* adalah mekanisme inspeksi dan remediasi keamanan berbasis PowerShell yang dirancang secara otomatis untuk perangkat keras berbasis sistem operasi Microsoft Windows 10 dan Windows 11 tingkat korporat. Skrip ini melakukan evaluasi status statis dan dinamis pada 24 kontrol keamanan fundamental. Sentinel mendukung dua mode operasional: evaluasi telemetri tanpa modifikasi (*Audit-Only*) serta penegakan konfigurasi sistem secara otomatis (*Remediation*).

---

# Bagian I. Pendahuluan & Spesifikasi Sistem

Pemeliharaan postur keamanan sistem secara konsisten di seluruh simpul *endpoint* terdistribusi memerlukan mekanisme inspeksi berbasis standar dan manajemen konfigurasi yang terintegrasi. Kerangka kerja *Sentinel* mengotomatisasi proses verifikasi serta pengerasan (*hardening*) parameter sistem utama, meliputi kebijakan kredensial lokal, perlindungan subsistem *Local Security Authority* (LSA), aturan *Windows Defender Firewall*, kapasitas log kejadian (*event log*), pembatasan *User Account Control* (UAC), tumpukan protokol jaringan, hingga profil operasional *Remote Desktop Protocol* (RDP).

## Ringkasan Spesifikasi Teknis

| Atribut | Detail Spesifikasi |  
| :--- | :--- |  
| *Nama Skrip* | `Sentinel.ps1` |  
| *Arsitektur Target* | x86_64 / ARM64 |  
| *Sistem Operasi* | Microsoft Windows 10, Windows 11 (Pro, Enterprise, Education) |  
| *Lingkungan Eksekusi* | Windows PowerShell 5.1+ / PowerShell Core 7.x |  
| *Persyaratan Hak Akses* | `Elevated Administrator` (`Security.Principal.WindowsBuiltInRole::Administrator`) |  
| *Apresiasi Standar Utama* | CIS Microsoft Windows 10/11 Benchmark v2.0.0+ |  

---

# Bagian II. Pemetaan Arsitektur & Cakupan Domain Kontrol

Logika evaluasi pada Sentinel memeriksa 24 parameter yang terbagi ke dalam 10 domain keamanan spesifik. Tabel I menampilkan pemetaan komprehensif dari kontrol internal skrip.

## Tabel I. Matriks Referensi Silang Domain Kontrol Keamanan dan Standar Internasional

| ID Seksi | Spesifikasi Domain | Referensi CIS Benchmark | Mekanisme Eksekusi / Kunci Registri Target |  
| :---: | :--- | :---: | :--- |  
| *1.1* | Panjang Minimum Kata Sandi | Kontrol 1.1.1 | Net Accounts (`/minpwlen:14`) |  
| *1.2* | Ambang Pemblokiran Akun | Kontrol 1.2.1 | Net Accounts (`/lockoutthreshold:5`, `/lockoutduration:15`) |  
| *1.1.1* | Kompleksitas Kata Sandi | Kontrol 1.1.2 | `HKLM:SYSTEMCurrentControlSetControlLsa` -> `ComplexityEnabled=1` |  
| *1.1.2* | Enkripsi Dapat Dibalik | Kontrol 1.1.3 | `HKLM:SYSTEMCurrentControlSetControlLsa` -> `ReversibleEncryptionEnabled=0` |  
| *2.1.1* | Akun Guest Bawaan | Kontrol 2.1.1 | `Disable-LocalUser -Name "Guest"` |  
| *2.1.2* | Akun Administrator Bawaan | Kontrol 2.1.2 | `Disable-LocalUser -Name "Administrator"` |  
| *2.2* | Penegakan Kebijakan Audit Lanjutan | Kontrol 2.2.1 | `SCENoApplyLegacyAuditPolicy=1` & Eksekusi Subkategori Auditpol |  
| *3.1* | Tingkat Autentikasi LAN Manager | Kontrol 2.3.11.7 | `HKLM:SYSTEMCurrentControlSetControlLsa` -> `LmCompatibilityLevel=5` |  
| *3.2* | Pembatasan Akses Anonim SAM | Kontrol 2.3.11.4 | `HKLM:SYSTEMCurrentControlSetControlLsa` -> `RestrictAnonymousSAM=1` |  
| *3.3* | Batas Waktu Inaktivitas Sesi | Kontrol 2.3.11.1 | `HKLM:SOFTWARE...PoliciesSystem` -> `InactivityTimeoutSecs=900` |  
| *3.4* | Keamanan Klien Minimum NTLM | Kontrol 2.3.11.9 | `HKLM:SYSTEM...LsaMSV1_0` -> `NTLMMinClientSec=537395200` |  
| *4.1* | Configuration Windows Defender Firewall | Kontrol 9.1 - 9.3 | Profil Domain, Private, Public diset `Block Inbound`, `LogBlocked=True` |  
| *5.0* | Kapasitas Ukuran Event Log | Kontrol 18.2 | Ekspansi `wevtutil` (App/Sys >= 32MB, Security >= 192MB) |  
| *6.1.1* | Penonaktifan Autentikasi WDigest | Kontrol 18.8.23.1 | `...ControlSecurityProvidersWDigest` -> `UseLogonCredential=0` |  
| *6.1.2* | Proteksi LSASS RunAsPPL | Kontrol 18.8.23.2 | `HKLM:SYSTEMCurrentControlSetControlLsa` -> `RunAsPPL=1` |  
| *6.2* | Verifikasi Enkripsi BitLocker | Kontrol 18.1.1 | Kueri `Get-BitLockerVolume -MountPoint "C:"` |  
| *7.1* | Penonaktifan Layanan Berisiko | Kontrol 5.1 - 5.7 | Mematikan `RemoteRegistry`, `Spooler`, `SSDPSRV`, `upnphost`, dll. |  
| *7.2* | Penegakan Layanan Utama | Kontrol 5.8 - 5.11 | Memastikan status `WinDefend`, `MpsSvc`, `EventLog`, `CryptSvc` berjalan |  
| *8.1* | Mode Persetujuan Admin UAC | Kontrol 2.3.17.1 | `...PoliciesSystem` -> `EnableLUA=1` |  
| *8.2* | Perilaku Elevasi Akses UAC | Kontrol 2.3.17.3 | `...PoliciesSystem` -> `ConsentPromptBehaviorAdmin=2` |  
| *8.3* | Penolakan Otomatis Pengguna UAC | Kontrol 2.3.17.4 | `...PoliciesSystem` -> `ConsentPromptBehaviorUser=0` |  
| *8.4* | Mode Desktop Aman UAC | Kontrol 2.3.17.5 | `...PoliciesSystem` -> `PromptOnSecureDesktop=1` |  
| *9.1* | Perlindungan AutoAdminLogon | Kontrol 18.9.3 | `...Winlogon` -> `AutoAdminLogon="0"` |  
| *9.2-4*| Pengerasan Protokol Jaringan | Kontrol 18.9.8 | Mematikan IP Source Routing, ICMP Redirects; Mengaktifkan Safe DLL Search |  
| *10.1* | Pengerasan Keamanan RDP | Kontrol 18.9.50 | Wajib NLA (`UserAuthentication=1`), Enkripsi Tingkat 3, Matikan Redireksi Drive |  
| *10.2* | Pencatatan Log PowerShell Script | Kontrol 18.9.84 | `...PowerShellScriptBlockLogging` -> `EnableScriptBlockLogging=1` |

---

# Bagian III. Metodologi Operasional & Mekanisme Eksekusi

## A. Verifikasi Prasyarat Hak Akses

Skrip melakukan validasi konteks identitas administrator sebelum proses pemeriksaan dimulai. Apabila eksekusi dijalankan tanpa hak akses administrator, skrip akan menghentikan proses secara otomatis:

```powershell  
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())  
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {  
    Write-Error "Harap jalankan skrip ini menggunakan PowerShell (Run as Administrator)!"  
    exit  
}
```  
### **B. Mode Eksekusi Operasional**

> 1. **Mode Audit Telemetri (Default)**  
>    Menjalankan kueri pembacaan status sistem tanpa mengubah nilai registri, status akun pengguna lokal, maupun konfigurasi layanan sistem bawaan.  
> 2. **Mode Remediation Otomatis (-Fix)**  
>    Melakukan penyesuaian parameter secara langsung. Kunci registri yang tidak sesuai akan diperbaiki menggunakan fungsi pembantu (Set-RegValue), kebijakan keamanan lokal disesuaikan menggunakan utilitas sistem (net, auditpol, wevtutil), dan layanan sistem yang berisiko akan dinonaktifkan secara otomatis.

## **Bagian IV. Panduan Penggunaan & Deploymen**

### **A. Eksekusi Jarak Jauh Langsung (PowerShell CLI)**

Eksekusi skrip secara langsung dari repositori GitHub melalui terminal PowerShell dengan hak akses administrator:

#### **1. Mode Audit Telemetri**

```PowerShell  
Invoke-Expression (Invoke-WebRequest -Uri "https://raw.githubusercontent.com/narendra-akmal/Sentinel/refs/heads/main/Sentinel.ps1" -UseBasicParsing).Content  
```  
#### **2. Mode Remediation Otomatis**

Untuk mengambil dan menjalankan perbaikan sistem secara langsung:

```PowerShell  
$script = (Invoke-WebRequest -Uri "https://raw.githubusercontent.com/narendra-akmal/Sentinel/refs/heads/main/Sentinel.ps1" -UseBasicParsing).Content ; Invoke-Command -ScriptBlock ([scriptblock]::Create($script)) -ArgumentList $true  

```  
### **B. Eksekusi dari Repositori Lokal**

> 1. Unduh atau salin berkas Sentinel.ps1 ke perangkat target.  
> 2. Buka Windows PowerShell sebagai **Administrator**.  
> 3. Jalankan perintah sesuai kebutuhan operasional:

```PowerShell  
# Menguji Audit Telemetri  
.Sentinel.ps1

# Menguji Audit & Remediasi Otomatis  
.Sentinel.ps1 -Fix
```  
## **Bagian V. Verifikasi & Output Kepatuhan**

Setelah proses eksekusi selesai, Sentinel menampilkan laporan terstruktur pada konsol dengan status kepatuhan (COMPLIANT, NON-COMPLIANT) beserta detail pendukung untuk keperluan jejak audit (*audit trail*).

```Plaintext  
======================================================================  
           SKRIP AUDIT & REMEDIASI KEAMANAN WINDOWS 10/11               
======================================================================  
[] Mode: AUDIT ONLY (Gunakan parameter -Fix untuk perbaikan)  
----------------------------------------------------------------------

[+] Checking Section 1: Account Policies...  
[1.1] Minimum Password Length (>=14) -> COMPLIANT  
    Detail: Current: 14  
[1.2] Account Lockout Threshold (<=5) -> COMPLIANT  
    Detail: Current: 5  
[1.1.1] Password Complexity Enabled -> COMPLIANT  
[1.1.2] Reversible Encryption Disabled -> COMPLIANT

... [output dipotong] ...

======================================================================  
                     AUDIT SELESAI DILAKUKAN                            
======================================================================
```  
## **Bagian VI. Pertimbangan Keamanan & Penafian**

* **Kesesuaian Manajemen Perubahan:** Eksekusi parameter -Fix mengubah konfigurasi administratif, status layanan sistem, dan kunci registri. Disarankan untuk melakukan pengujian pada lingkungan *staging* sebelum mendistribusikan skrip secara luas melalui *Group Policy Objects* (GPO) atau Microsoft Intune.  
* **Enkripsi BitLocker (Kontrol 6.2):** Status enkripsi BitLocker dievaluasi secara otomatis; namun proses aktivasi memerlukan inisialisasi TPM hardware serta kebijakan kunci pemulihan (*recovery key*) yang dikonfigurasi secara terpisah.

##📄 Lisensi
<p>Proyek ini didistribusikan di bawah lisensi <strong>MIT License</strong>. Anda bebas menggunakan, memodifikasi, mendistribusikan, dan memanfaatkannya secara komersial maupun pribadi tanpa batasan. Lihat berkas <a href="LICENSE">LICENSE</a> untuk informasi lebih lanjut.</p>
