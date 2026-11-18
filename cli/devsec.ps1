<#
.SYNOPSIS
    DevSecOps Toolkit CLI for Windows PowerShell (Zero-Dependency)
.DESCRIPTION
    Multi-Vendor Firewall Transpiler, CIDR Calculator, SOC Log Scanner & Secret Generator.
.EXAMPLE
    .\cli\devsec.ps1 -Command firewall -Vendor fortigate -Name "ZT-ISOLATE-IOT" -Src "10.99.0.0/24" -Dst "0.0.0.0/0" -Action deny
    .\cli\devsec.ps1 -Command scan-log -Text "185.220.101.45 GET /login?id=1' OR '1'='1 CVE-2024-3400"
    .\cli\devsec.ps1 -Command secret -Text "ZeroTrust2026"
#>
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("firewall", "scan-log", "secret")]
    [string]$Command,

    [ValidateSet("fortigate", "pfsense", "aruba", "linux")]
    [string]$Vendor = "fortigate",

    [string]$Name = "ZT-ISOLATE-IOT",
    [ValidateSet("accept", "deny")]
    [string]$Action = "deny",
    [string]$Src = "10.99.0.0/24",
    [string]$Dst = "0.0.0.0/0",
    [int]$Vlan = 99,
    [string]$Text = ""
)

$ErrorActionPreference = "Stop"

if ($Command -eq "firewall") {
    $isAllow = ($Action -eq "accept")
    if ($Vendor -eq "fortigate") {
        $fgAct = if ($isAllow) { "accept" } else { "deny" }
        Write-Output @"
config firewall policy
    edit 0
        set name "$Name"
        set srcintf "vlan$Vlan"
        set dstintf "wan1"
        set action $fgAct
        set srcaddr "$Src"
        set dstaddr "$Dst"
        set schedule "always"
        set service "ALL"
        set logtraffic all
    next
end
"@
    } elseif ($Vendor -eq "pfsense") {
        $pfAct = if ($isAllow) { "pass" } else { "block drop" }
        Write-Output "$pfAct in log quick on `$vlan$Vlan inet from $Src to $Dst label `"$Name`""
    } elseif ($Vendor -eq "aruba") {
        $aclAct = if ($isAllow) { "permit" } else { "deny" }
        Write-Output "ip access-list extended `"ACL_$Name`"`n   10 $aclAct ip $Src $Dst log"
    } elseif ($Vendor -eq "linux") {
        $iptAct = if ($isAllow) { "ACCEPT" } else { "DROP" }
        Write-Output "iptables -A FORWARD -s $Src -d $Dst -j $iptAct"
    }
}
elseif ($Command -eq "scan-log") {
    $ips = [regex]::Matches($Text, "\b(?:\d{1,3}\.){3}\d{1,3}\b") | ForEach-Object { $_.Value } | Select-Object -Unique
    $cves = [regex]::Matches($Text, "CVE-\d{4}-\d{4,7}", "IgnoreCase") | ForEach-Object { $_.Value.ToUpper() } | Select-Object -Unique
    $alerts = @()
    if ($Text -match "UNION\s+SELECT|OR\s+'1'='1'|sqlmap") { $alerts += "SQL Injection (SQLi)" }
    if ($Text -match "\.\./|/etc/passwd") { $alerts += "Path Traversal (LFI)" }
    if ($Text -match "AKIA[0-9A-Z]{16}") { $alerts += "AWS Access Key Leak" }

    $report = [ordered]@{
        extracted_ips = @($ips)
        cves          = @($cves)
        alerts        = @($alerts)
    }
    $report | ConvertTo-Json -Depth 4
}
elseif ($Command -eq "secret") {
    $bytes = New-Object byte[] 18
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $hex = ($bytes | ForEach-Object { $_.ToString("x2") }) -join ""
    $sha256 = ""
    if ($Text) {
        $hashBytes = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text))
        $sha256 = ($hashBytes | ForEach-Object { $_.ToString("x2") }) -join ""
    }
    $out = [ordered]@{
        uuid_v4 = [guid]::NewGuid().ToString()
        api_key = "dsk_live_$hex"
        sha256  = $sha256
    }
    $out | ConvertTo-Json
}
