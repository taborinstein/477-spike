<#
=============================================================================
  ftps_attack.ps1 -- on-path eavesdropping attack against the FTPS server,
                     native Windows (no WSL).

  Same attack as the plaintext demo, now vs TLS: the sniffer captures the
  loopback while an FTPS client logs in and downloads the exam. Because the
  control + data channels are inside TLS, the capture is ciphertext and the
  attacker recovers nothing.

    attacker = dumpcap on the Npcap loopback adapter (passive tap)
    victim   = curl.exe --ssl-reqd (an FTPS client)
    server   = ftps_server.py (pyftpdlib TLS_FTPHandler)

  PREREQS
    * Python with pyftpdlib + pyopenssl + cryptography
    * Wireshark installed WITH Npcap's "Support loopback traffic capture"
      (gives dumpcap + tshark + the loopback adapter)
    * curl.exe (built into Windows 10/11)
    * ftps_server.py, make_cert.py, and root\exam.txt in THIS folder

  RUN (in an elevated PowerShell / VS Code terminal -- capture needs admin):
    powershell -ExecutionPolicy Bypass -File .\ftps_attack.ps1
=============================================================================
#>
[CmdletBinding()]
param(
  [string]$FtpHost        = "127.0.0.1",
  [int]   $Port           = 2121,
  [string]$User           = "student",
  [string]$Pass           = "RHITspr26!exam",
  [int]   $CaptureSeconds = 12
)

$ErrorActionPreference = "Stop"
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Here
$CapDir = Join-Path $Here "capture"
$Pcap   = Join-Path $CapDir "ftps_session.pcap"
$DL     = Join-Path $CapDir "victim_dl.txt"

function Hdr($t){ Write-Host "`n>>> $t" -ForegroundColor Cyan }
function Note($t){ Write-Host "    $t" -ForegroundColor DarkGray }
function Resolve-Tool($name,$fallbacks){
  $c = Get-Command $name -ErrorAction SilentlyContinue
  if($c){ return $c.Source }
  foreach($f in $fallbacks){ if(Test-Path $f){ return $f } }
  return $null
}

# --- tools ---
$ws      = "C:\Program Files\Wireshark"
$tshark  = Resolve-Tool "tshark"  @("$ws\tshark.exe")
$dumpcap = Resolve-Tool "dumpcap" @("$ws\dumpcap.exe")
$curl    = Resolve-Tool "curl.exe" @("$env:WINDIR\System32\curl.exe")   # NOT the PS 'curl' alias
$python  = Resolve-Tool "python" @(); if(-not $python){ $python = Resolve-Tool "py" @() }

$fatal=@()
if(-not $tshark -or -not $dumpcap){ $fatal += "Wireshark (tshark/dumpcap) not found -- install Wireshark incl. Npcap." }
if(-not $curl){ $fatal += "curl.exe not found." }
if(-not $python){ $fatal += "Python not found on PATH." }
if(-not (Test-Path (Join-Path $Here "ftps_server.py"))){ $fatal += "ftps_server.py not found in $Here." }
if($fatal){ $fatal | ForEach-Object { Write-Host "ERROR: $_" -ForegroundColor Red }; exit 1 }

# --- make sure the server has what it needs ---
if(-not (Test-Path (Join-Path $Here "root"))){ New-Item -ItemType Directory -Path (Join-Path $Here "root") | Out-Null }
if(-not (Test-Path (Join-Path $Here "root\exam.txt"))){
  Set-Content -Path (Join-Path $Here "root\exam.txt") -Encoding ascii -Value "TOP SECRET EXAM`r`nAnswer to Q1: 42"
}
if(-not (Test-Path (Join-Path $Here "cert.pem"))){
  Note "generating cert.pem/key.pem (make_cert.py)"
  & $python (Join-Path $Here "make_cert.py") | Out-Null
}

Remove-Item -Recurse -Force $CapDir -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $CapDir | Out-Null

# --- find the Npcap loopback adapter ---
$loop = (& $dumpcap -D 2>$null | Where-Object { $_ -match 'loopback' } | Select-Object -First 1)
if(-not $loop){
  Write-Host "ERROR: no Npcap loopback adapter. Re-run the Npcap installer with 'Support loopback traffic capture'." -ForegroundColor Red
  exit 1
}
$ifaceId = ($loop -split '\.')[0].Trim()

Write-Host "ATTACK vs FTPS" -ForegroundColor White
Note "target ftp(es)://${FtpHost}:${Port}   loopback adapter #$ifaceId"
$serverProc = $null
try {
  # 1. victim FTPS server
  Hdr "Phase 1 -- start the victim FTPS server"
  $serverProc = Start-Process -FilePath $python -ArgumentList @("ftps_server.py") `
      -WorkingDirectory $Here -RedirectStandardOutput (Join-Path $CapDir "server.out.log") `
      -RedirectStandardError (Join-Path $CapDir "server.err.log") -PassThru -WindowStyle Hidden
  $up=$false
  for($i=0;$i -lt 60;$i++){ try{ $c=New-Object Net.Sockets.TcpClient; $c.Connect($FtpHost,$Port); $c.Close(); $up=$true; break }catch{ Start-Sleep -Milliseconds 200 } }
  if(-not $up){ Write-Host "ERROR: server did not start; see $CapDir\server.err.log" -ForegroundColor Red; exit 1 }
  Note "server up (TLS required on control + data)"

  # 2. attacker taps the wire
  Hdr "Phase 2 -- attacker taps loopback (dumpcap)"
  $cap = Start-Process -FilePath $dumpcap `
      -ArgumentList @("-i","$ifaceId","-w","$Pcap","-a","duration:$CaptureSeconds","-f","tcp","-q") `
      -PassThru -WindowStyle Hidden
  Start-Sleep -Seconds 1
  if($cap.HasExited){ Write-Host "ERROR: dumpcap exited (run elevated for capture)." -ForegroundColor Red; exit 1 }
  Note "capturing to $Pcap -- attacker only listens"

  # 3. victim FTPS session
  Hdr "Phase 3 -- victim logs in and downloads over FTPS (curl.exe)"
  & $curl -sS --ssl-reqd -k --user "${User}:${Pass}" "ftp://${FtpHost}:${Port}/exam.txt" -o $DL
  if(Test-Path $DL){ Note "victim received exam.txt ($((Get-Item $DL).Length) bytes)" }

  # 4. stop capture
  Hdr "Phase 4 -- stop the capture"
  Wait-Process -Id $cap.Id -Timeout ($CaptureSeconds+10) -ErrorAction SilentlyContinue
  if(-not $cap.HasExited){ Stop-Process -Id $cap.Id -Force -ErrorAction SilentlyContinue }
  Start-Sleep -Milliseconds 300
  Note "captured -> $Pcap"

  # 5. what did the attacker learn?  (scan the raw capture bytes for plaintext)
  Hdr "Phase 5 -- what did the attacker learn?"
  $ascii = [System.Text.Encoding]::ASCII.GetString([System.IO.File]::ReadAllBytes($Pcap))
  if( ($ascii -match [regex]::Escape($Pass)) -or ($ascii -match 'TOP SECRET') ){
    Write-Host "    LEAK: plaintext recovered from the capture!" -ForegroundColor Red
  } else {
    Write-Host "    NO LEAK -- password and exam are NOT in the capture." -ForegroundColor Green
  }
  Note "FTP commands still readable in clear (pre-TLS only):"
  & $tshark -r $Pcap -d "tcp.port==$Port,ftp" -Y "ftp.request" -T fields -e ftp.request.command -e ftp.request.arg 2>$null |
      Where-Object { $_ -match '\S' } | ForEach-Object { Write-Host "      $_" }
  Note "...everything after AUTH is TLS application data (encrypted)."

  # 6. raw control stream on the wire
  Hdr "Phase 6 -- the control stream as it crossed the wire"
  $ctrl = & $tshark -r $Pcap -d "tcp.port==$Port,ftp" -Y "tcp.port==$Port" -T fields -e tcp.stream 2>$null | Select-Object -First 1
  if(-not $ctrl){ $ctrl = 0 }
  & $tshark -r $Pcap -q -z "follow,tcp,ascii,$ctrl" 2>$null | Select-Object -First 28 | ForEach-Object { Write-Host "      $_" }

  Hdr "Result"
  Write-Host "The capture that cracked plaintext FTP now yields only the handshake"
  Write-Host "(220 ready, AUTH TLS, 234) in the clear; credentials + exam are inside TLS."
  Write-Host "Passive eavesdropping is defeated."
  Write-Host ""
  Write-Host "Note: an ACTIVE MITM (fake cert) would also fail -- UNLESS the client" -ForegroundColor DarkGray
  Write-Host "trusts all certs (ftpsTrustAllCerts=true). That flag is the one hole left." -ForegroundColor DarkGray
}
finally {
  if($serverProc -and -not $serverProc.HasExited){ Stop-Process -Id $serverProc.Id -Force -ErrorAction SilentlyContinue }
}