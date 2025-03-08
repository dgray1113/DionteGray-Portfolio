# Script: Scan-OpenPorts.ps1
# Description: Scans a network range for open ports and logs vulnerabilities

#region Configuration
$ipRange = "192.168.1.1-192.168.1.10"  # Replace with your network range (ethical use only)
$ports = @(22, 80, 443, 3389)          # Common ports: SSH, HTTP, HTTPS, RDP
`\(logFile = "Network_Scan_Log_\)`((Get-Date -Format 'yyyyMMdd_HHmmss')).txt"
`\(reportPath = "OpenPorts_Report_\)`((Get-Date -Format 'yyyyMMdd_HHmmss')).csv"
$timeoutMs = 500                       # Timeout in milliseconds per port test
#endregion

#region Functions
function Write-Log {
    param ([string]`\(Message, [string]\)`Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "`\(timestamp - [\)`Level] - $Message" | Out-File -FilePath $logFile -Append
}

function Test-Port {
    param ([string]`\(IP, [int]\)`Port)
    try {
        $test = Test-NetConnection -ComputerName $IP -Port $Port -InformationLevel Quiet -WarningAction SilentlyContinue -ErrorAction Stop
        return $test
    } catch {
        Write-Log -Message "Error testing `\(IP:\)`Port - $_" -Level "ERROR"
        return $false
    }
}
#endregion

#region Main Execution
try {
    Write-Host "Starting network port scan..." -ForegroundColor Green
    Write-Log -Message "Port scan initiated for range $ipRange"

    # Parse IP range
    $startIP, $endIP = $ipRange.Split('-')
    `\(start = [System.Net.IPAddress]::Parse(\)`startIP).GetAddressBytes()[-1]
    `\(end = [System.Net.IPAddress]::Parse(\)`endIP).GetAddressBytes()[-1]
    $baseIP = $startIP.Substring(0, $startIP.LastIndexOf('.') + 1)
    $results = @()

    # Scan each IP and port
    for ($i = $start; $i -le $end; $i++) {
        `\(currentIP = "\)`baseIP$i"
        Write-Host "Scanning $currentIP..." -ForegroundColor Yellow

        foreach ($port in $ports) {
            $isOpen = Test-Port -IP $currentIP -Port $port
            if ($isOpen) {
                $result = [PSCustomObject]@{
                    IPAddress    = $currentIP
                    Port         = $port
                    Status       = "Open"
                    Service      = switch ($port) { 22 {"SSH"}; 80 {"HTTP"}; 443 {"HTTPS"}; 3389 {"RDP"}; default {"Unknown"} }
                    Recommendation = "Review if $port should be open; consider firewall rules."
                }
                $results += $result
                Write-Host "Open port detected: `\(currentIP:\)`port (`\((\)`result.Service))" -ForegroundColor Red
                Write-Log -Message "Open port found: `\(currentIP:\)`port (`\((\)`result.Service))" -Level "WARNING"
            }
        }
    }

    # Generate report
    if ($results) {
        $results | Export-Csv -Path $reportPath -NoTypeInformation -ErrorAction Stop
        Write-Host "Report saved to $reportPath" -ForegroundColor Cyan
        Write-Log -Message "Scan completed, report saved to $reportPath" -Level "INFO"
    } else {
        Write-Host "No open ports detected in range." -ForegroundColor Green
        Write-Log -Message "No vulnerabilities found" -Level "INFO"
    }
} catch {
    Write-Host "Critical error: $_" -ForegroundColor Red
    Write-Log -Message "Scan failed: $_" -Level "ERROR"
} finally {
    Write-Log -Message "Port scan session ended"
}
#endregion
