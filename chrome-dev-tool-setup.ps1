[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateRange(1,65535)]
    [int]$Port = 9229,
    
    [Parameter(Mandatory=$false)]
    [string]$ListenAddress = "172.30.10.54",
    
    [Parameter(Mandatory=$false)]
    [string]$RemoteIP = "172.30.10.53",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("Local","Remote")]
    [string]$Mode
)

$ErrorActionPreference = "Stop"

$script:ShutdownRequested = $false
$script:BoundArgs = @{}
foreach ($key in $PSBoundParameters.Keys) {
    $script:BoundArgs[$key] = $true
}

$script:Session = [ordered]@{
    Port = $Port
    ListenAddress = $ListenAddress
    RemoteIP = $RemoteIP
    Mode = $Mode
    ProfileDir = $null
}
$script:CleanupNeeded = $false

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Read-IntWithDefault {
    param(
        [string]$Prompt,
        [int]$Default
    )

    while ($true) {
        $response = Read-Host "$Prompt [default: $Default]"
        if ([string]::IsNullOrWhiteSpace($response)) {
            return $Default
        }

        $value = 0
        if ([int]::TryParse($response, [ref]$value) -and $value -ge 1 -and $value -le 65535) {
            return $value
        }

        Write-Host "[WARN] Please enter a valid port number between 1 and 65535." -ForegroundColor Yellow
    }
}

function Read-StringWithDefault {
    param(
        [string]$Prompt,
        [string]$Default
    )

    $response = Read-Host "$Prompt [default: $Default]"
    if ([string]::IsNullOrWhiteSpace($response)) {
        return $Default
    }

    return $response.Trim()
}

function Get-UserInputs {
    Write-Host ""
    Write-Host "=== Chrome Remote Debugging Manager ===" -ForegroundColor Cyan
    Write-Host "Configure local or remote debugging endpoints." -ForegroundColor White
    Write-Host ""

    if (-not $script:Session.Mode) {
        Write-Host "Select Mode:" -ForegroundColor Yellow
        Write-Host "  1) Local  - Launch Chrome with debugging on localhost" -ForegroundColor Gray
        Write-Host "  2) Remote - Chrome plus port proxy and firewall" -ForegroundColor Gray

        while ($true) {
            $choice = (Read-Host "Enter mode [default: 2]").Trim()
            if ([string]::IsNullOrWhiteSpace($choice)) {
                $script:Session.Mode = "Remote"
            }
            else {
                switch ($choice) {
                    "1" { $script:Session.Mode = "Local" }
                    "2" { $script:Session.Mode = "Remote" }
                    default {
                        Write-Host "[WARN] Invalid selection. Please enter 1 or 2." -ForegroundColor Yellow
                    }
                }
            }

            if ($script:Session.Mode) {
                break
            }
        }
    }

    if (-not $script:BoundArgs.ContainsKey("Port")) {
        $script:Session.Port = Read-IntWithDefault -Prompt "Enter port number" -Default $script:Session.Port
    }

    if ($script:Session.Mode -eq "Remote") {
        if (-not $script:BoundArgs.ContainsKey("ListenAddress")) {
            $script:Session.ListenAddress = Read-StringWithDefault -Prompt "Enter listen address" -Default $script:Session.ListenAddress
        }

        if (-not $script:BoundArgs.ContainsKey("RemoteIP")) {
            $script:Session.RemoteIP = Read-StringWithDefault -Prompt "Enter remote IP to allow" -Default $script:Session.RemoteIP
        }
    }

    Write-Host ""
    Write-Host "Configuration:" -ForegroundColor Green
    Write-Host ("  Mode:   {0}" -f $script:Session.Mode) -ForegroundColor Gray
    Write-Host ("  Port:   {0}" -f $script:Session.Port) -ForegroundColor Gray
    if ($script:Session.Mode -eq "Remote") {
        Write-Host ("  Listen: {0}" -f $script:Session.ListenAddress) -ForegroundColor Gray
        Write-Host ("  Remote: {0}" -f $script:Session.RemoteIP) -ForegroundColor Gray
    }
    Write-Host ""
}

function Get-ChromePath {
    $paths = @(
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe"
    )

    foreach ($path in $paths) {
        if (Test-Path $path) {
            return $path
        }
    }

    throw "Chrome executable not found. Update the script with the correct path."
}

function Get-ChromeProcessByPort {
    param([int]$Port)

    $processMatches = @()

    try {
        $processMatches = Get-Process chrome -ErrorAction Stop | Where-Object {
            $_.CommandLine -and $_.CommandLine -like "*--remote-debugging-port=$Port*"
        }
    }
    catch {
        $processMatches = @()
    }

    if ($processMatches -and $processMatches.Count -gt 0) {
        return $processMatches
    }

    try {
        $cimMatches = Get-CimInstance Win32_Process -Filter "Name='chrome.exe'" -ErrorAction Stop | Where-Object {
            $_.CommandLine -and $_.CommandLine -like "*--remote-debugging-port=$Port*"
        }

        return $cimMatches | ForEach-Object {
            [PSCustomObject]@{
                Id = $_.ProcessId
                CommandLine = $_.CommandLine
                Name = $_.Name
            }
        }
    }
    catch {
        return @()
    }
}

function Test-PortProxy {
    param(
        [int]$Port,
        [string]$ListenAddress
    )

    $output = & netsh interface portproxy show v4tov4 2>$null
    if (-not $output) {
        return $false
    }

    $pattern = [regex]::Escape($ListenAddress) + "\s+" + $Port
    return $output | Select-String -Pattern $pattern -Quiet
}

function Test-FirewallRule {
    param([int]$Port)

    $ruleName = "Chrome CDP $Port"
    $output = & netsh advfirewall firewall show rule name="$ruleName" 2>$null
    if (-not $output) {
        return $false
    }

    return $output | Select-String -Pattern "Rule Name" -Quiet
}

function Add-PortProxy {
    param(
        [int]$Port,
        [string]$ListenAddress
    )

    netsh interface portproxy add v4tov4 listenport=$Port listenaddress=$ListenAddress connectport=$Port connectaddress=127.0.0.1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to configure port proxy for ${ListenAddress}:${Port}."
    }
}

function Remove-PortProxy {
    param(
        [int]$Port,
        [string]$ListenAddress,
        [switch]$Quiet
    )

    if (-not (Test-PortProxy -Port $Port -ListenAddress $ListenAddress)) {
        if (-not $Quiet) {
            Write-Host "[INFO] No port proxy to remove." -ForegroundColor Gray
        }
        return
    }

    netsh interface portproxy delete v4tov4 listenport=$Port listenaddress=$ListenAddress | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to remove port proxy for ${ListenAddress}:${Port}."
    }

    if (-not $Quiet) {
        Write-Host "[OK] Removed port proxy." -ForegroundColor Green
    }
}

function Add-FirewallRule {
    param(
        [int]$Port,
        [string]$RemoteIP
    )

    $ruleName = "Chrome CDP $Port"
    & netsh advfirewall firewall add rule name="$ruleName" dir=in action=allow protocol=TCP localport=$Port remoteip=$RemoteIP | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to add firewall rule $ruleName."
    }
}

function Remove-FirewallRule {
    param(
        [int]$Port,
        [switch]$Quiet
    )

    if (-not (Test-FirewallRule -Port $Port)) {
        if (-not $Quiet) {
            Write-Host "[INFO] No firewall rule to remove." -ForegroundColor Gray
        }
        return
    }

    $ruleName = "Chrome CDP $Port"
    & netsh advfirewall firewall delete rule name="$ruleName" | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to remove firewall rule $ruleName."
    }

    if (-not $Quiet) {
        Write-Host "[OK] Removed firewall rule." -ForegroundColor Green
    }
}

function Stop-ChromeDebug {
    param(
        [switch]$Quiet,
        [switch]$ForceNetworkCleanup
    )

    if (-not $Quiet) {
        Write-Host ""
        Write-Host "=== Stopping Chrome Remote Debugging ===" -ForegroundColor Yellow
    }

    $processes = Get-ChromeProcessByPort -Port $script:Session.Port
    foreach ($proc in $processes) {
        try {
            Stop-Process -Id $proc.Id -Force -ErrorAction Stop
            if (-not $Quiet) {
                Write-Host ("[OK] Stopped Chrome process (PID {0})" -f $proc.Id) -ForegroundColor Green
            }
        }
        catch {
            if (-not $Quiet) {
                Write-Host ("[WARN] Unable to stop process {0}: {1}" -f $proc.Id, $_.Exception.Message) -ForegroundColor Yellow
            }
        }
    }

    $removeNetwork = $ForceNetworkCleanup.IsPresent -or $script:Session.Mode -eq "Remote"
    if ($removeNetwork) {
        Remove-PortProxy -Port $script:Session.Port -ListenAddress $script:Session.ListenAddress -Quiet:$Quiet
        Remove-FirewallRule -Port $script:Session.Port -Quiet:$Quiet
    }

    if ($script:Session.ProfileDir -and (Test-Path $script:Session.ProfileDir)) {
        $removed = $false
        for ($i = 0; $i -lt 3 -and -not $removed; $i++) {
            try {
                Remove-Item -Path $script:Session.ProfileDir -Recurse -Force -ErrorAction Stop
                $removed = $true
            }
            catch {
                if ($i -lt 2) {
                    Start-Sleep -Milliseconds 500
                } elseif (-not $Quiet) {
                    Write-Host "[WARN] Unable to remove the temporary Chrome profile directory." -ForegroundColor Yellow
                }
            }
        }
    }

    if (-not $Quiet) {
        Write-Host "[INFO] Cleanup complete." -ForegroundColor Green
    }
}

function Resolve-Conflicts {
    param(
        [bool]$HasProcess,
        [bool]$HasProxy,
        [bool]$HasFirewall
    )

    $needsCleanup = ($HasProcess -eq $true) -or ($HasProxy -eq $true) -or ($HasFirewall -eq $true)
    if (-not $needsCleanup) {
        return @{ Continue = $true; AlternatePort = $null; Abort = $false }
    }

    Write-Host "=== Conflict Detected ===" -ForegroundColor Yellow
    if ($HasProcess) {
        Write-Host "- Chrome already listening on port $($script:Session.Port)." -ForegroundColor Gray
    }
    if ($HasProxy) {
        Write-Host "- Port proxy exists for $($script:Session.ListenAddress):$($script:Session.Port)." -ForegroundColor Gray
    }
    if ($HasFirewall) {
        Write-Host "- Firewall rule 'Chrome CDP $($script:Session.Port)' already present." -ForegroundColor Gray
    }

    $choice = $null
    while ($null -eq $choice) {
        $answer = (Read-Host "Proceed by removing conflicts? (Y)es / (C)hoose new port / (N)o").Trim().ToUpperInvariant()
        switch ($answer) {
            "Y" { $choice = 'cleanup' }
            "C" { $choice = 'alternate' }
            "N" { $choice = 'abort' }
            default { Write-Host "[WARN] Please respond with Y, C, or N." -ForegroundColor Yellow }
        }
    }

    if ($choice -eq 'cleanup') {
        return @{ Continue = $true; AlternatePort = $null; Abort = $false }
    }
    elseif ($choice -eq 'alternate') {
        while ($true) {
            $newPort = Read-IntWithDefault -Prompt "Enter alternate port" -Default $script:Session.Port
            if ($newPort -eq $script:Session.Port) {
                Write-Host "[WARN] Alternate port must differ from the current port." -ForegroundColor Yellow
                continue
            }
            $script:Session.Port = $newPort
            Write-Host ("[OK] Using alternate port {0}." -f $script:Session.Port) -ForegroundColor Green
            return @{ Continue = $false; AlternatePort = $script:Session.Port; Abort = $false }
        }
    }

    return @{ Continue = $false; AlternatePort = $null; Abort = $true }
}

function Stop-ExistingInstances {
    Write-Host "=== Checking for existing instances ===" -ForegroundColor Yellow

    $processes = Get-ChromeProcessByPort -Port $script:Session.Port
    $proxyExists = Test-PortProxy -Port $script:Session.Port -ListenAddress $script:Session.ListenAddress
    $ruleExists = Test-FirewallRule -Port $script:Session.Port

    if (-not $processes -and -not $proxyExists -and -not $ruleExists) {
        Write-Host "[OK] No existing instances found." -ForegroundColor Green
        Write-Host ""
        return
    }

    $decision = Resolve-Conflicts -HasProcess ([bool]$processes) -HasProxy ([bool]$proxyExists) -HasFirewall ([bool]$ruleExists)

    if ($decision.Abort) {
        throw [System.OperationCanceledException]"User aborted due to existing conflicts."
    }

    if ($decision.AlternatePort) {
        Write-Host "[INFO] Re-running conflict check with alternate port..." -ForegroundColor Cyan
        Stop-ExistingInstances
        return
    }

    if ($decision.Continue) {
        Write-Host "[INFO] Cleaning up previous run..." -ForegroundColor Cyan
        Stop-ChromeDebug -Quiet -ForceNetworkCleanup
        Start-Sleep -Seconds 2
        Write-Host ""
    }
}

function Show-RunningStatus {
    param([DateTime]$StartTime)

    $elapsed = (Get-Date) - $StartTime
    $status = "{0:00}:{1:00}:{2:00}" -f [math]::Floor($elapsed.TotalHours), $elapsed.Minutes, $elapsed.Seconds
    Write-Host -NoNewline ("`r[RUNNING] Elapsed: {0}  (Ctrl+C to stop) " -f $status)
}

function Start-DebugMonitor {
    $startTime = Get-Date
    $lastCheck = $startTime

    Write-Host "=== Monitoring Active Session ===" -ForegroundColor Cyan
    Write-Host "Chrome remote debugging is running." -ForegroundColor White
    Write-Host "Press Ctrl+C to exit and clean up." -ForegroundColor Yellow
    Write-Host ""

    while (-not $script:ShutdownRequested) {
        Show-RunningStatus -StartTime $startTime

        if ((Get-Date) -ge $lastCheck.AddSeconds(5)) {
            if (-not (Get-ChromeProcessByPort -Port $script:Session.Port)) {
                Write-Host "`n[WARN] Chrome debug process has stopped." -ForegroundColor Yellow
                $script:ShutdownRequested = $true
            }
            $lastCheck = Get-Date
        }

        Start-Sleep -Milliseconds 500
    }
}

function Start-ChromeDebug {
    $script:CleanupNeeded = $true
    $chromePath = Get-ChromePath
    $uniqueSuffix = [Guid]::NewGuid().ToString("N")
    $script:Session.ProfileDir = Join-Path -Path $env:TEMP -ChildPath ("chrome-remote-profile-{0}-{1}" -f $script:Session.Port, $uniqueSuffix)

    if (Test-Path $script:Session.ProfileDir) {
        Remove-Item -Path $script:Session.ProfileDir -Recurse -Force
    }

    Write-Host "=== Starting Chrome Remote Debugging ===" -ForegroundColor Green

    Write-Host ("[1/4] Launching Chrome on port {0}..." -f $script:Session.Port) -ForegroundColor Cyan
    Start-Process -FilePath $chromePath -ArgumentList @(
        "--remote-debugging-port=$($script:Session.Port)",
        "--user-data-dir=$($script:Session.ProfileDir)",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-ipv6",
        "--disable-dev-shm-usage"
    ) | Out-Null
    Start-Sleep -Seconds 1

    $processDetected = $false
    $deadline = (Get-Date).AddSeconds(15)
    while ((Get-Date) -lt $deadline) {
        if (Get-ChromeProcessByPort -Port $script:Session.Port) {
            $processDetected = $true
            break
        }
        Start-Sleep -Milliseconds 500
    }

    if (-not $processDetected) {
        throw "Chrome process not detected."
    }

    Write-Host "[OK] Chrome started." -ForegroundColor Green

    $stepIndex = 1
    if ($script:Session.Mode -eq "Remote") {
        $stepIndex++
        Write-Host ("[{0}/4] Configuring port proxy..." -f $stepIndex) -ForegroundColor Cyan
        Write-Host ("[INFO] Forwarding {0}:{1} -> 127.0.0.1:{1}" -f $script:Session.ListenAddress, $script:Session.Port) -ForegroundColor Gray
        Add-PortProxy -Port $script:Session.Port -ListenAddress $script:Session.ListenAddress
        Write-Host "[OK] Port proxy configured." -ForegroundColor Green

        $stepIndex++
        Write-Host ("[{0}/4] Adding firewall rule..." -f $stepIndex) -ForegroundColor Cyan
        Write-Host ("[INFO] Allowing {0} to access port {1}" -f $script:Session.RemoteIP, $script:Session.Port) -ForegroundColor Gray
        Add-FirewallRule -Port $script:Session.Port -RemoteIP $script:Session.RemoteIP
        Write-Host "[OK] Firewall rule added." -ForegroundColor Green
    }

    Write-Host "[INFO] Verifying setup..." -ForegroundColor Cyan
    if (-not (Get-ChromeProcessByPort -Port $script:Session.Port)) {
        throw "Chrome process not detected after startup."
    }

    if ($script:Session.Mode -eq "Remote") {
        if (-not (Test-PortProxy -Port $script:Session.Port -ListenAddress $script:Session.ListenAddress)) {
            throw "Port proxy verification failed."
        }
        if (-not (Test-FirewallRule -Port $script:Session.Port)) {
            throw "Firewall rule verification failed."
        }
    }

    Write-Host ""
    Write-Host "Chrome remote debugging endpoints:" -ForegroundColor White
    Write-Host ("  Local : 127.0.0.1:{0}" -f $script:Session.Port) -ForegroundColor Gray
    if ($script:Session.Mode -eq "Remote") {
        Write-Host ("  Remote: {0}:{1}" -f $script:Session.ListenAddress, $script:Session.Port) -ForegroundColor Gray
        Write-Host ("  Allowed remote IP: {0}" -f $script:Session.RemoteIP) -ForegroundColor Gray
    }
    Write-Host ""
}

if (-not (Test-Administrator)) {
    Write-Host ""
    Write-Host "ERROR: This script must be run as Administrator." -ForegroundColor Red
    Write-Host "Launch PowerShell as Administrator and run the script again." -ForegroundColor Yellow
    exit 1
}

try {
    Get-UserInputs
    Stop-ExistingInstances
    Start-ChromeDebug
    Start-DebugMonitor
}
catch [System.OperationCanceledException] {
    Write-Host ""
    Write-Host "[INFO] Operation canceled by user before starting Chrome." -ForegroundColor Yellow
}
catch {
    Write-Host ""
    Write-Host ("[ERROR] {0}" -f $_.Exception.Message) -ForegroundColor Red
}
finally {
    if ($script:CleanupNeeded) {
        try {
            Stop-ChromeDebug
        }
        catch {
            Write-Host ("[WARN] Cleanup encountered an error: {0}" -f $_.Exception.Message) -ForegroundColor Yellow
        }
    }
    else {
        Write-Host ""
        Write-Host "[INFO] No resources were started; skipping cleanup." -ForegroundColor Gray
    }

    Write-Host ""
    Write-Host "Press Enter to exit..."
    Read-Host | Out-Null
}
