# =============================================================================
# Get-AttackerGeodata.ps1
# Azure Sentinel SOC & Honeynet — Attacker Geolocation Enrichment Script
# Author: Nathaniel Osei-Baffour
#
# Description:
#   Reads failed RDP login attempts from the Windows Security Event Log (Event ID 4625),
#   extracts attacker IP addresses, resolves their geographic location via a free
#   geolocation API, and writes enriched log entries to a custom log file for
#   ingestion into a Log Analytics Workspace / Microsoft Sentinel.
#
# Requirements:
#   - Run on the honeypot VM with PowerShell 5.1+
#   - Free API key from https://ipgeolocation.io
#   - Log Analytics Workspace configured to ingest custom logs
# =============================================================================

# ── Configuration ─────────────────────────────────────────────────────────────

$API_KEY        = "YOUR_API_KEY_HERE"           # ipgeolocation.io free API key
$OUTPUT_LOG     = "C:\ProgramData\failed_rdp.log"  # Custom log file path (ingested by Log Analytics)
$POLL_INTERVAL  = 30                            # Seconds between polling cycles

# ── Helper: Write structured log entry ────────────────────────────────────────

function Write-GeoLog {
    param (
        [string]$Timestamp,
        [string]$EventId,
        [string]$SourceIP,
        [string]$Username,
        [string]$Country,
        [string]$State,
        [string]$City,
        [string]$Latitude,
        [string]$Longitude,
        [string]$CountryCode
    )

    $entry = "latitude={0},longitude={1},destinationhost=honeypot-vm,username={2},sourcehost={3},state={4},country={5},label={6},{7},timestamp={8}" -f `
        $Latitude, $Longitude, $Username, $SourceIP, $State, $Country, "$Country - $SourceIP", $CountryCode, $Timestamp

    Add-Content -Path $OUTPUT_LOG -Value $entry
}

# ── Helper: Resolve IP to geolocation ─────────────────────────────────────────

function Get-Geolocation {
    param ([string]$IPAddress)

    # Return placeholder for private/loopback IPs
    if ($IPAddress -match '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|::1|-)') {
        return [PSCustomObject]@{
            country_name  = "Private Network"
            state_prov    = "N/A"
            city          = "N/A"
            latitude      = "0"
            longitude     = "0"
            country_code2 = "N/A"
        }
    }

    try {
        $uri      = "https://api.ipgeolocation.io/ipgeo?apiKey=$API_KEY&ip=$IPAddress"
        $response = Invoke-RestMethod -Uri $uri -Method Get -ErrorAction Stop
        return $response
    }
    catch {
        Write-Warning "Geolocation lookup failed for IP: $IPAddress — $_"
        return $null
    }
}

# ── Helper: Get failed RDP events from Security Log ───────────────────────────

function Get-FailedRDPEvents {
    # Event ID 4625 = An account failed to log on
    $filter = @{
        LogName   = "Security"
        Id        = 4625
        StartTime = (Get-Date).AddMinutes(-5)   # Look back 5 minutes each cycle
    }

    try {
        $events = Get-WinEvent -FilterHashtable $filter -ErrorAction SilentlyContinue
        return $events
    }
    catch {
        return @()
    }
}

# ── Helper: Parse IP and Username from event XML ──────────────────────────────

function Parse-EventDetails {
    param ($Event)

    $xml      = [xml]$Event.ToXml()
    $data     = $xml.Event.EventData.Data

    $username = ($data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
    $ip       = ($data | Where-Object { $_.Name -eq "IpAddress"      }).'#text'

    return [PSCustomObject]@{
        Username  = if ($username) { $username } else { "unknown" }
        IPAddress = if ($ip)       { $ip       } else { "-"       }
    }
}

# ── Initialize log file with header if it doesn't exist ───────────────────────

if (-not (Test-Path $OUTPUT_LOG)) {
    $header = "latitude=0,longitude=0,destinationhost=samplehost,username=sampleuser,sourcehost=0.0.0.0,state=samplestate,country=samplenation,label=samplenation - 0.0.0.0,timestamp=2024-01-01 00:00:00"
    Set-Content -Path $OUTPUT_LOG -Value $header
    Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Log file initialized at $OUTPUT_LOG"
}

# ── Track already-processed events to avoid duplicates ────────────────────────

$processedEvents = @{}

# ── Main polling loop ──────────────────────────────────────────────────────────

Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Starting attacker geolocation monitor..."
Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Polling every $POLL_INTERVAL seconds. Press Ctrl+C to stop."
Write-Host ""

while ($true) {

    $events = Get-FailedRDPEvents

    if ($events.Count -gt 0) {
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Found $($events.Count) failed login event(s) in last 5 min."
    }

    foreach ($event in $events) {

        # Skip already-processed events using RecordId as unique key
        if ($processedEvents.ContainsKey($event.RecordId)) { continue }
        $processedEvents[$event.RecordId] = $true

        $details = Parse-EventDetails -Event $event

        if ($details.IPAddress -eq "-") { continue }

        Write-Host "  [+] Failed login | User: $($details.Username) | IP: $($details.IPAddress)" -ForegroundColor Yellow

        # Geolocation lookup
        $geo = Get-Geolocation -IPAddress $details.IPAddress

        if ($geo) {
            Write-Host "      └─ Location: $($geo.city), $($geo.state_prov), $($geo.country_name)" -ForegroundColor Cyan

            Write-GeoLog `
                -Timestamp   ($event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")) `
                -EventId     $event.Id `
                -SourceIP    $details.IPAddress `
                -Username    $details.Username `
                -Country     $geo.country_name `
                -State       $geo.state_prov `
                -City        $geo.city `
                -Latitude    $geo.latitude `
                -Longitude   $geo.longitude `
                -CountryCode $geo.country_code2
        }
    }

    Start-Sleep -Seconds $POLL_INTERVAL
}
