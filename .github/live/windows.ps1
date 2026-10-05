# Live test on Windows: the machine's own SMB server shares the target
# folder on port 445, smbproxy listens on 4445 in front of it, and the
# Windows SMB client maps the proxy's shares through the alternative port
# that Windows Server 2025 and Windows 11 24H2 support. Then the client
# copies large files directly and through the proxy to compare speeds.
#
# Run from the repository root, with .\smbproxy.exe built, on a throwaway
# machine: it adds a local user, shares a folder and maps drives.

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$here = $PSScriptRoot
function live { python "$here\live.py" @args; if ($LASTEXITCODE) { throw "live.py $($args[0]) failed" } }
function step($text) { Write-Host "`n=== $text" }

$root = "C:\smbtest"           # the target's share
$work = Join-Path $env:RUNNER_TEMP "smblive"
$tuser = "smbtarget"           # target account, created here
$tpass = "TargetPw2026x"
$puser = "tester"              # proxy logins
$ppass = "ProxyPw2026x"
$ouser = "other"
$opass = "OtherPw2026x"
$port = 4445
# The client keeps one connection, with one login, per server name, so the
# proxy and the target are reached under different names.
$proxyHost = "smbproxy-live"
$targetHost = "localhost"
$size = if ($env:LIVE_SPEED_MIB) { [int]$env:LIVE_SPEED_MIB } else { 512 }
$runs = if ($env:LIVE_SPEED_RUNS) { [int]$env:LIVE_SPEED_RUNS } else { 3 }

function Map($drive, $server, $share, $user, $pass, $tcpPort) {
    $a = @{ LocalPath = "${drive}:"; RemotePath = "\\$server\$share"; UserName = $user; Password = $pass; Persistent = $false }
    if ($tcpPort) { $a.TcpPort = $tcpPort }
    New-SmbMapping @a | Out-Null
}

function Unmap($drive) { Remove-SmbMapping -LocalPath "${drive}:" -Force -UpdateProfile }

function Refused($what, [scriptblock]$fn) {
    try { & $fn } catch { Write-Host "refused as expected: $($_.Exception.Message)"; return }
    throw "$what was not refused"
}

New-Item -ItemType Directory -Force $work | Out-Null
$proxy = $null
try {
    step "Set up the target share"
    New-Item -ItemType Directory -Force "$root\rw", "$root\ro", "$root\secret" | Out-Null
    Set-Content -NoNewline -Path "$root\ro\readme.txt" -Value "read me`n"
    Set-Content -NoNewline -Path "$root\secret\secret.txt" -Value "secret`n"
    net user $tuser $tpass /add /y
    if ($LASTEXITCODE) { throw "net user failed" }
    icacls $root /grant "${tuser}:(OI)(CI)F" | Out-Null
    if ($LASTEXITCODE) { throw "icacls failed" }
    New-SmbShare -Name data -Path $root -FullAccess $tuser | Out-Null
    Get-SmbServerConfiguration | Format-List RequireSecuritySignature, EnableSMB2Protocol, EncryptData
    Get-SmbClientConfiguration | Format-List RequireSecuritySignature, EnableInsecureGuestLogons
    Add-Content "$env:SystemRoot\System32\drivers\etc\hosts" "`n127.0.0.1 $proxyHost"

    step "Start smbproxy"
    live config --out "$work\live.yaml" --listen "127.0.0.1:$port" `
        --host 127.0.0.1 --port 445 --user $tuser --domain $env:COMPUTERNAME --password $tpass --share data `
        --proxy-user $puser --proxy-password $ppass --other-user $ouser --other-password $opass
    .\smbproxy.exe -version
    $proxy = Start-Process -FilePath .\smbproxy.exe -ArgumentList "-config", "$work\live.yaml" `
        -RedirectStandardError "$work\proxy.log" -RedirectStandardOutput "$work\proxy.out" -PassThru -NoNewWindow
    live wait --port $port

    # A wrong password first: once a mapping exists, the client reuses its
    # login for every share of that server.
    step "A wrong password is refused"
    Refused "a wrong password" { Map P $proxyHost rw $puser "wrong" $port }

    step "Map the shares"
    Map P $proxyHost rw $puser $ppass $port
    Map R $proxyHost ro $puser $ppass $port
    Get-SmbMapping | Format-Table -AutoSize
    Get-SmbConnection | Format-Table -AutoSize

    step "A share outside read_access is refused"
    Refused "the secret share" { Map S $proxyHost secret $puser $ppass $port }

    step "List shares"
    $view = net view "\\$proxyHost" /all 2>&1 | Out-String
    Write-Host $view
    if ($LASTEXITCODE) {
        Write-Host "::warning::net view \\$proxyHost failed; it may not reuse the alternative port"
    } else {
        if ($view -notmatch "(?m)^rw\s+Disk" -or $view -notmatch "(?m)^ro\s+Disk") { throw "rw or ro not listed" }
        if ($view -match "(?m)^secret\s") { throw "secret is listed to $puser" }
    }

    step "File-system tests"
    live fs --mount "P:\" --target "$root\rw" --ro-mount "R:\" --ro-target "$root\ro"

    step "Unmap the shares"
    Unmap P
    Unmap R
    if (Get-SmbMapping | Where-Object LocalPath -in "P:", "R:") { throw "still mapped" }

    step "Speed, direct and through the proxy"
    1..$runs | ForEach-Object { live mkfile --path "$root\rw\speed-src-$_.bin" --size-mib $size }
    foreach ($i in 1..$runs) {
        Map T $targetHost data $tuser $tpass
        live speed --dir "T:\rw" --src "speed-src-$i.bin" --label direct --size-mib $size --out "$work\speed.jsonl"
        Unmap T
        Map P $proxyHost rw $puser $ppass $port
        live speed --dir "P:\" --src "speed-src-$i.bin" --label proxy --size-mib $size --out "$work\speed.jsonl"
        Unmap P
    }

    step "Small files, direct and through the proxy"
    Map T $targetHost data $tuser $tpass
    live bench-dir --dir "T:\rw" --label direct --out "$work\dir.jsonl"
    Unmap T
    Map P $proxyHost rw $puser $ppass $port
    live bench-dir --dir "P:\" --label proxy --out "$work\dir.jsonl"
    Unmap P

    $report = python "$here\live.py" report --results "$work\speed.jsonl" --dir-results "$work\dir.jsonl" `
        --title "Windows: Windows SMB client, Windows target" --size-mib $size | Out-String
    Write-Host $report
    if ($env:GITHUB_STEP_SUMMARY) { Add-Content $env:GITHUB_STEP_SUMMARY $report }
} finally {
    Get-SmbMapping -ErrorAction SilentlyContinue | Remove-SmbMapping -Force -ErrorAction SilentlyContinue
    if ($proxy) { Stop-Process -Id $proxy.Id -ErrorAction SilentlyContinue }
    Get-Content "$work\proxy.log", "$work\proxy.out" -ErrorAction SilentlyContinue | Set-Content proxy.log
}
