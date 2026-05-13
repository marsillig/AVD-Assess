<#
.SYNOPSIS
    AVD-Assess - Azure Virtual Desktop health checker.

.DESCRIPTION
    Connects to an Azure subscription, runs 16 best-practice checks against Azure
    Virtual Desktop (AVD) host pools, session hosts, scaling plans, and related
    resources, and produces a self-contained HTML report with traffic-light
    scoring and remediation guidance across Cost, Reliability, Security, and
    Operational Excellence.

.PARAMETER SubscriptionId
    Azure subscription ID to assess. If not provided, uses the current Az context.

.PARAMETER TenantId
    Azure tenant ID. If not provided, uses the current Az context.

.PARAMETER OutputPath
    Where to save the HTML report. Defaults to the current directory with a
    timestamped filename: AVD-Assess-Report-yyyyMMdd-HHmmss.html

.PARAMETER HostPoolName
    Optional: scope the assessment to a single host pool by name.
    Must be used with -ResourceGroupName.

.PARAMETER ResourceGroupName
    Optional: scope the assessment to a specific resource group.

.PARAMETER UseExistingConnection
    Skip Connect-AzAccount and use the existing Az PowerShell context.

.PARAMETER OpenReport
    Open the HTML report in the default browser when complete.

.PARAMETER DryRun
    Generate a report using synthetic data - no Azure calls are made. Used for
    HTML layout verification and for contributors testing UI changes.

.PARAMETER FSLogixStorageAccount
    Optional: name of the storage account hosting FSLogix profile containers.
    If supplied, this overrides tag-based and name-pattern auto-discovery for
    every host pool. Use for one-off runs against environments where the
    FSLogix storage is not tagged.

.PARAMETER FSLogixTagName
    Host pool tag key that names the FSLogix storage account. Defaults to
    'FSLogixStorageAccount'. AVD-Assess proposes this as a community
    convention - no Microsoft-blessed standard exists.

.PARAMETER FSLogixNamePattern
    Wildcard pattern used to identify FSLogix storage accounts by name when
    neither -FSLogixStorageAccount nor a tag match is found. Defaults to
    '*fslogix*' (case-insensitive). Set to an empty string to disable
    name-pattern discovery.

.EXAMPLE
    .\AVD-Assess.ps1
    Run against all host pools in the current Az context.

.EXAMPLE
    .\AVD-Assess.ps1 -SubscriptionId "00000000-0000-0000-0000-000000000000" -OpenReport

.EXAMPLE
    .\AVD-Assess.ps1 -HostPoolName "hp-prod-pooled-01" -ResourceGroupName "rg-avd-prod"

.EXAMPLE
    .\AVD-Assess.ps1 -UseExistingConnection -OutputPath "C:\Reports\avd-health.html"

.NOTES
    Author   : Wayne Bellows (wayne_bellows@hotmail.com)
    Website  : https://modern-euc.com
    Project  : https://github.com/waynebellows/AVD-Assess
    License  : MIT
    Version  : 2.0.0-alpha.1
#>

[CmdletBinding()]
param(
    [string]$SubscriptionId,
    [string]$TenantId,
    [string]$OutputPath,
    [string]$HostPoolName,
    [string]$ResourceGroupName,
    [switch]$UseExistingConnection,
    [switch]$OpenReport,
    [switch]$DryRun,
    [string]$FSLogixStorageAccount,
    [string]$FSLogixTagName    = 'FSLogixStorageAccount',
    [string]$FSLogixNamePattern = '*fslogix*'
)

$ErrorActionPreference = 'Stop'

$script:ToolVersion = '2.0.0-alpha.1'
$script:ProjectUrl  = 'https://github.com/waynebellows/AVD-Assess'
$script:WebsiteUrl  = 'https://modern-euc.com'
$script:RequiredModules = @(
    'Az.Accounts',
    'Az.DesktopVirtualization',
    'Az.Compute',
    'Az.Monitor',
    'Az.Resources',
    'Az.Network',
    'Az.Storage',
    'Az.Security'
)

# ==============================================================================
# CHECK CATALOG
# ==============================================================================
#
# Single source of truth for each check's display name, canonical remediation
# text, and Microsoft Learn URL. Read by both the real check functions and the
# dry-run seeder so the two stay in sync.
#
# Special-case remediations (e.g. "Grant Reader role…" when a permission fetch
# fails) are kept inline at the call site rather than catalogued, because they
# describe *why* a fetch failed and aren't part of the check's primary advice.

$script:CheckCatalog = @{

    # ---- Cost Optimisation ----
    ScalingPlanCoverage = [PSCustomObject]@{
        Name        = 'Scaling Plan Coverage'
        Remediation = 'Create and assign a scaling plan to each pooled host pool. Scaling plans can reduce Azure compute costs by 40-70% for environments with predictable daily usage patterns by automatically deallocating idle session hosts outside peak hours.'
        LearnMore   = 'https://learn.microsoft.com/en-us/azure/virtual-desktop/autoscale-scaling-plan'
    }

    StartVmOnConnect = [PSCustomObject]@{
        Name        = 'Start VM on Connect (Personal Host Pools)'
        Remediation = 'Enable Start VM on Connect on all personal host pools. This ensures personal VMs are only running when users need them, rather than 24/7. Combine with an auto-shutdown schedule for maximum savings. A personal VM running 24/7 costs approximately 3x more than one using Start VM on Connect with an 8-hour working day pattern.'
        LearnMore   = 'https://learn.microsoft.com/en-us/azure/virtual-desktop/start-virtual-machine-connect'
    }

    UnhealthyHostsInRotation = [PSCustomObject]@{
        Name        = 'Unhealthy Hosts in Session Rotation'
        Remediation = 'Set AllowNewSession = false on unhealthy hosts to drain them from the load balancer. This prevents new users from connecting to broken session hosts. Investigate the underlying health issue (check AVD agent logs at C:\Program Files\Microsoft RDAgent\) and either remediate the VM or replace the session host.'
        LearnMore   = 'https://learn.microsoft.com/en-us/azure/virtual-desktop/drain-mode'
    }

    MaxSessionLimit = [PSCustomObject]@{
        Name        = 'Max Session Limit Configuration'
        Remediation = 'Set a realistic max session limit based on your VM size and workload type. Recommended starting points: D4s_v5 (4 vCPU / 16 GB) - 8-12 sessions for knowledge workers, 12-16 for task workers. D8s_v5 (8 vCPU / 32 GB) - 16-24 sessions for knowledge workers. Setting an appropriate limit enables the load balancer to start new session hosts before existing ones become overloaded.'
        LearnMore   = 'https://learn.microsoft.com/en-us/azure/virtual-desktop/configure-host-pool-load-balancing'
    }

    # ---- Reliability & Resilience ----
    SessionHostHealth = [PSCustomObject]@{
        Name        = 'Session Host Health'
        Remediation = 'Investigate unhealthy session hosts using AVD Insights in the Azure portal (if diagnostic settings are configured) or by reviewing the AVD agent log directly on the affected VM at C:\Program Files\Microsoft RDAgent\. Common causes: domain trust relationship lost, FSLogix health failures, AVD agent crash, or underlying VM disk/network issues. Consider enabling AVD health alerts via Azure Monitor.'
        LearnMore   = 'https://learn.microsoft.com/en-us/azure/virtual-desktop/troubleshoot-session-host-in-use'
    }

    RdpShortpath = [PSCustomObject]@{
        Name        = 'RDP Shortpath / Network Auto-Detect'
        Remediation = 'Add networkautodetect:i:1 and bandwidthautodetect:i:1 to the Custom RDP Properties of each host pool. These settings enable RDP Shortpath (UDP), which provides significantly lower latency, better audio/video quality, and improved session resilience compared to the TCP Reverse Connect fallback. Also ensure UDP port 3478 (STUN) is permitted outbound at the firewall for public network Shortpath.'
        LearnMore   = 'https://learn.microsoft.com/en-us/azure/virtual-desktop/rdp-shortpath'
    }

    AgentUpdateRing = [PSCustomObject]@{
        Name                       = 'Agent Update Ring'
        # Default to the more common case (no validation pools); the real check
        # function picks RemediationAllValidation when every pool is on validation.
        Remediation                = 'Mark at least one non-production or low-risk host pool as a Validation environment in its properties. Validation ring pools receive AVD agent updates 1-2 weeks before the production ring, giving you an early warning of any issues before they affect all users.'
        RemediationAllValidation   = 'Move your production host pools off the Validation ring. Only canary, dev, or test host pools should be in Validation. Production users should be on the standard update ring for maximum stability.'
        LearnMore                  = 'https://learn.microsoft.com/en-us/azure/virtual-desktop/configure-validation-environment'
    }

    SessionCapacityHeadroom = [PSCustomObject]@{
        Name        = 'Session Capacity Headroom'
        Remediation = 'Add session hosts to the over-capacity pool(s), or review whether the max session limit is set too high relative to available VM resources. Also review the scaling plan ramp-up schedule to ensure hosts are started before peak demand rather than in response to it - proactive scaling prevents the headroom problem entirely.'
        LearnMore   = 'https://learn.microsoft.com/en-us/azure/virtual-desktop/autoscale-scaling-plan'
    }

    # ---- Security Posture ----
    DriveRedirection = [PSCustomObject]@{
        Name        = 'Drive Redirection Policy'
        Remediation = 'Review the drivestoredirect RDP property on each flagged host pool. Set drivestoredirect:s: (empty value) to disable drive redirection entirely, or drivestoredirect:s:DynamicDrives to allow only removable drives (USB). In regulated environments (financial services, healthcare, government), drive redirection should be explicitly disabled unless a business case exists and it is documented.'
        LearnMore   = 'https://learn.microsoft.com/en-us/azure/virtual-desktop/rdp-properties'
    }

    ClipboardRedirection = [PSCustomObject]@{
        Name        = 'Clipboard Redirection Policy'
        Remediation = 'If clipboard access is not required for user productivity or is prohibited by your data security policy, set redirectclipboard:i:0 in host pool RDP properties. This is particularly important for environments handling sensitive personal or financial data where copy/paste to local devices would represent a compliance risk.'
        LearnMore   = 'https://learn.microsoft.com/en-us/azure/virtual-desktop/rdp-properties'
    }

    TrustedLaunch = [PSCustomObject]@{
        Name        = 'Trusted Launch / Secure Boot'
        Remediation = 'New session host deployments should use Trusted Launch (enabled by default for Gen2 VMs in Azure). For existing VMs, Microsoft now supports migration to Trusted Launch for Gen2 VMs without redeployment. See the Learn More link for the migration process. Trusted Launch enables Secure Boot (prevents unsigned bootloaders and drivers) and vTPM (supports attestation and BitLocker).'
        LearnMore   = 'https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch-existing-vm'
    }

    EntraIdJoin = [PSCustomObject]@{
        Name        = 'Entra ID Join Status'
        Remediation = 'Evaluate migrating new host pool deployments to Entra ID join. This eliminates line-of-sight dependency on domain controllers, simplifies the identity architecture, and enables Conditional Access at the session level. Note: FSLogix profiles, MSIX App Attach, and some legacy applications may require additional planning for Entra ID join scenarios.'
        LearnMore   = 'https://learn.microsoft.com/en-us/azure/virtual-desktop/deploy-azure-ad-joined-vm'
    }

    DefenderForCloudCoverage = [PSCustomObject]@{
        Name        = 'Defender for Cloud Coverage'
        Remediation = 'Enable Microsoft Defender for Cloud at the Standard tier for at least Servers (VirtualMachines plan) and Storage on the assessed subscription. Defender for Servers gives you vulnerability assessment, file integrity monitoring, just-in-time VM access, and adaptive application controls - none of which fire in Free tier. Defender for Storage adds malware scanning and sensitive data discovery for FSLogix profile shares and app attach storage. Enable via the Azure portal (Defender for Cloud > Environment settings > <subscription> > Defender plans) or with Set-AzSecurityPricing -Name VirtualMachines -PricingTier Standard. Cost is per resource per month - review the pricing page before enabling at scale.'
        LearnMore   = 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/defender-for-cloud-introduction'
    }

    AvdPrivateLink = [PSCustomObject]@{
        Name        = 'AVD Private Link'
        Remediation = 'For each flagged host pool, either disable public network access (Update-AzWvdHostPool -PublicNetworkAccess Disabled) or deploy a private endpoint that targets the host pool resource. Private Link replaces the public AVD control plane endpoint with a private IP inside your VNet, which removes the public attack surface for connection brokering and feed enumeration. Public network access is the default on host pools created before the Private Link GA, so legacy deployments commonly fall foul of this check even though their session hosts themselves are not public. Pairs naturally with workspace and feed Private Link endpoints for a fully private user experience.'
        LearnMore   = 'https://learn.microsoft.com/en-us/azure/virtual-desktop/private-link-overview'
    }

    # ---- Operational Excellence ----
    DiagnosticSettings = [PSCustomObject]@{
        Name        = 'Diagnostic Settings'
        Remediation = 'Configure diagnostic settings on each flagged host pool to send the following log categories to a Log Analytics workspace: Connection, HostRegistration, Error, Management, AgentHealthStatus. This is a prerequisite for AVD Insights and enables troubleshooting of connection failures, performance issues, and agent problems. Without diagnostic logs, you are flying blind.'
        LearnMore   = 'https://learn.microsoft.com/en-us/azure/virtual-desktop/diagnostics-log-analytics'
    }

    ResourceTagging = [PSCustomObject]@{
        Name        = 'Resource Tagging'
        Remediation = 'Apply the following tags to all AVD resources (host pools, session hosts, workspaces, storage accounts): Environment (e.g. Production, Development, Test) and Owner (team or person responsible). Consider using Azure Policy with a DeployIfNotExists or Deny effect to enforce tagging at resource creation. Good tagging enables cost analysis by environment in Azure Cost Management.'
        LearnMore   = 'https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/tag-resources'
    }

    AgentUpdateState = [PSCustomObject]@{
        Name        = 'AVD Agent Update State'
        Remediation = 'Investigate agent update failures on the affected session hosts. Start by reviewing the RDAgent log at C:\Program Files\Microsoft RDAgent\AgentInstall.txt. Common causes: Windows Update failing to install prerequisites, a network proxy blocking the agent download endpoint (*.wvd.microsoft.com), antivirus blocking the installer, or the VM needing a restart. After resolving, restart the RDAgentBootLoader service to retry the update.'
        LearnMore   = 'https://learn.microsoft.com/en-us/azure/virtual-desktop/troubleshoot-agent'
    }

    ServiceHealthAlerts = [PSCustomObject]@{
        Name        = 'Service Health Alerts'
        Remediation = 'Create at least one Azure Service Health activity log alert that covers Azure Virtual Desktop on this subscription. In the Azure portal: Service Health > Service health alerts > Add service health alert, scope it to this subscription, pick "Azure Virtual Desktop" under Services (or leave Services blank to cover all services), tick the event types you want notified on (Service issue, Planned maintenance, Health advisory, Security advisory), and attach an action group that notifies your operations channel. Most AVD outages and maintenance windows are knowable in advance through Service Health - alerts turn that knowledge into a notification before users start reporting symptoms.'
        LearnMore   = 'https://learn.microsoft.com/en-us/azure/virtual-desktop/set-up-service-alerts'
    }

    LoadBalancingAlgorithm = [PSCustomObject]@{
        Name        = 'Load Balancing Algorithm'
        Remediation = 'BreadthFirst is recommended when user experience is the top priority - each user gets more dedicated resources. DepthFirst is recommended when cost is the priority and the workload is not resource-intensive - it allows more VMs to be fully shut down during off-peak hours. Review your choice against your scaling plan configuration: DepthFirst works best with aggressive scale-in, BreadthFirst pairs well with reserved instances on a core set of always-on hosts.'
        LearnMore   = 'https://learn.microsoft.com/en-us/azure/virtual-desktop/configure-host-pool-load-balancing'
    }

    # ---- Performance Efficiency ----
    AcceleratedNetworking = [PSCustomObject]@{
        Name        = 'Accelerated Networking'
        Remediation = 'Enable Accelerated Networking on every session host NIC. For VMs that support it (most Dsv3 / Dsv4 / Dsv5 / Esv4 / Esv5 sizes and above), this offloads packet processing to the host SmartNIC and typically halves end-to-end network latency. Stop the VM, run Set-AzNetworkInterface with -EnableAcceleratedNetworking $true on the NIC, then start the VM. Bake it into your deployment templates so new hosts are correctly configured from day one. If a VM SKU does not support Accelerated Networking, consider resizing to a modern SKU as part of your next refresh cycle.'
        LearnMore   = 'https://learn.microsoft.com/en-us/azure/virtual-network/accelerated-networking-overview'
    }

    PremiumOsDisk = [PSCustomObject]@{
        Name        = 'OS Disk Performance Tier'
        Remediation = 'Move multi-session host pool OS disks to Premium SSD (Premium_LRS) at minimum. Sub-premium OS disks are the #1 cause of slow logon and laggy session experience on pooled hosts. To migrate: deallocate the VM, change the OS disk SKU via the Azure portal or Update-AzDisk -DiskSku Premium_LRS, then start the VM. Bake Premium_LRS into your deployment templates. For personal desktops, Standard SSD may be acceptable per WAF guidance, but Premium SSD still wins for logon and app launch performance.'
        LearnMore   = 'https://learn.microsoft.com/en-us/azure/well-architected/azure-virtual-desktop/storage'
    }

    Gen2VirtualMachines = [PSCustomObject]@{
        Name        = 'VM Generation (Gen2)'
        Remediation = 'Plan a refresh of any Gen1 session host VMs to Gen2 images. Gen1 blocks Trusted Launch, Confidential VMs, vTPM, and several Windows 11 features, and indicates the underlying image lineage is stale (Azure has defaulted to Gen2 since 2022). Generation is set at deployment time and cannot be changed in place - the migration path is to deploy fresh session hosts from a Gen2-based image, drain the Gen1 hosts, then retire them. If your image build pipeline still produces Gen1, update the source image SKU to a Gen2 equivalent (most marketplace images now offer a "-g2" variant).'
        LearnMore   = 'https://learn.microsoft.com/en-us/azure/virtual-machines/generation-2'
    }

    FSLogixRegionColocation = [PSCustomObject]@{
        Name        = 'FSLogix Region Colocation'
        Remediation = 'Move the FSLogix profile storage account into the same Azure region as the host pool it serves. Cross-region FSLogix traffic adds 40-80 ms to every OpenFile against the profile container - which means every application launch and Outlook search in the user session takes that hit. Migration path: provision a new storage account in the target region, use AzCopy or Storage Mover to copy profile containers in a maintenance window, repoint the FSLogix VHDLocations registry value, then decommission the old account. If you cannot move the storage, consider deploying a regional session host pool that lives next to the profile data instead.'
        LearnMore   = 'https://learn.microsoft.com/en-us/azure/well-architected/azure-virtual-desktop/storage'
    }

    AvailabilityZoneDistribution = [PSCustomObject]@{
        Name        = 'Availability Zone Distribution'
        Remediation = 'Deploy multi-session host pools with session hosts spread across at least two availability zones. New deployments: select explicit zones (1, 2, 3) for each VM in the pool, or use a Virtual Machine Scale Set with the Spread placement group policy. Existing single-zone pools: provision additional hosts in alternate zones, drain users from the original zone, then retire the single-zone hosts. The host pool itself does not have a zone property - zone distribution is a property of the underlying VMs. Some Azure regions do not yet support availability zones - if you are in one of those regions, plan to migrate the host pool to a zone-capable region as part of your DR strategy.'
        LearnMore   = 'https://learn.microsoft.com/en-us/azure/reliability/availability-zones-overview'
    }

    FSLogixProfileRedundancy = [PSCustomObject]@{
        Name        = 'FSLogix Profile Redundancy'
        Remediation = 'Move FSLogix profile storage to a zone-redundant SKU: Standard_ZRS, Standard_GZRS, Standard_RAGZRS, or Premium_ZRS. LRS storage takes a full outage when its single AZ has a problem - even if the session host pool itself spans multiple zones, users on LRS profiles get locked out. ZRS replicates synchronously across three AZs in the region for the same use case. For Premium file shares (the recommended FSLogix backend at scale), use Premium_ZRS. SKU changes are non-disruptive on most account types but verify Microsoft Learn for your specific configuration before scheduling.'
        LearnMore   = 'https://learn.microsoft.com/en-us/azure/storage/common/storage-redundancy'
    }
}

function Get-Check {
    # Returns the catalog entry for a check ID. Throws on unknown IDs so typos
    # surface immediately rather than producing reports with blank fields.
    param([Parameter(Mandatory)][string]$Id)
    if (-not $script:CheckCatalog.ContainsKey($Id)) {
        throw "Unknown check ID '$Id'. Catalog keys: $(($script:CheckCatalog.Keys | Sort-Object) -join ', ')"
    }
    return $script:CheckCatalog[$Id]
}

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

$script:Checks = [System.Collections.Generic.List[object]]::new()

function Add-CheckResult {
    param(
        [Parameter(Mandatory)][ValidateSet('Cost','Reliability','Security','Operations','Performance')]
        [string]$Category,
        [Parameter(Mandatory)][string]$CheckName,
        [Parameter(Mandatory)][ValidateSet('Pass','Warning','Fail','Info')]
        [string]$Status,
        [Parameter(Mandatory)][ValidateRange(0,100)][int]$Score,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Finding,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Remediation,
        [AllowEmptyString()][string]$LearnMore = ''
    )
    $script:Checks.Add([PSCustomObject]@{
        Category    = $Category
        CheckName   = $CheckName
        Status      = $Status
        Score       = $Score
        Finding     = $Finding
        Remediation = $Remediation
        LearnMore   = $LearnMore
    })

    $colour = switch ($Status) {
        'Pass'    { 'Green' }
        'Warning' { 'Yellow' }
        'Fail'    { 'Red' }
        'Info'    { 'Cyan' }
    }
    $tag = switch ($Status) {
        'Pass'    { '[PASS]' }
        'Warning' { '[WARN]' }
        'Fail'    { '[FAIL]' }
        'Info'    { '[INFO]' }
    }
    Write-Host ('  {0} {1}' -f $tag, $CheckName) -ForegroundColor $colour
}

function Write-Section {
    param([string]$Title)
    $underline = '-' * $Title.Length
    Write-Host ''
    Write-Host "  $Title"      -ForegroundColor White
    Write-Host "  $underline" -ForegroundColor DarkGray
}

function Write-Banner {
    $v = $script:ToolVersion
    $verLine = "  |           AVD-Assess  v{0,-22}|" -f $v
    Write-Host ''
    Write-Host '  +----------------------------------------------+' -ForegroundColor Cyan
    Write-Host $verLine                                              -ForegroundColor Cyan
    Write-Host '  |  Azure Virtual Desktop Health Checker        |' -ForegroundColor Cyan
    Write-Host '  |  modern-euc.com                              |' -ForegroundColor Cyan
    Write-Host '  |  github.com/waynebellows/AVD-Assess          |' -ForegroundColor Cyan
    Write-Host '  +----------------------------------------------+' -ForegroundColor Cyan
    Write-Host ''
}

function Get-RdpProperty {
    param([string]$RdpString, [string]$PropertyName)
    if ([string]::IsNullOrEmpty($RdpString)) { return $null }
    $match = $RdpString -split ';' | Where-Object { $_ -match "^$([regex]::Escape($PropertyName)):" }
    if ($match) {
        $parts = $match -split ':', 3
        if ($parts.Count -ge 3) { return $parts[2] }
    }
    return $null
}

function Get-RgFromArmId {
    # Extracts the resource group name from an ARM resource ID. ARM IDs have the
    # shape: /subscriptions/<sub>/resourceGroups/<rg>/providers/<...>
    param([Parameter(Mandatory)][string]$ResourceId)
    $parts = $ResourceId -split '/'
    if ($parts.Count -ge 5) { return $parts[4] }
    throw "Cannot extract resource group from ARM ID: $ResourceId"
}

function Invoke-WithRetry {
    # Wraps a scriptblock in a small retry loop with exponential backoff. Retries
    # on transient ARM throttling (HTTP 429) and gateway timeouts; surfaces other
    # errors immediately so genuine failures still throw quickly.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][scriptblock]$ScriptBlock,
        [int]$MaxAttempts = 3,
        [int]$InitialDelaySeconds = 2,
        [string]$OperationName = 'Azure operation'
    )
    $attempt = 0
    $delay   = $InitialDelaySeconds
    while ($true) {
        $attempt++
        try {
            return & $ScriptBlock
        } catch {
            $msg = $_.Exception.Message
            $isTransient = $msg -match '\b(429|TooManyRequests|throttl|timeout|GatewayTimeout|ServiceUnavailable|503)\b'
            if (-not $isTransient -or $attempt -ge $MaxAttempts) {
                throw
            }
            Write-Verbose "$OperationName attempt $attempt failed (transient): $msg. Retrying in $delay s."
            Start-Sleep -Seconds $delay
            $delay = [math]::Min($delay * 2, 30)
        }
    }
}

function Get-ScoreColour {
    param([int]$Score)
    if ($Score -ge 80) { return '#B3FF00' }  # lime green
    elseif ($Score -ge 60) { return '#33CCCC' }  # teal
    elseif ($Score -ge 40) { return '#f59e0b' }  # amber
    else { return '#ef4444' }                    # red
}

function ConvertTo-HtmlSafe {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    return $Text `
        -replace '&', '&amp;' `
        -replace '<', '&lt;' `
        -replace '>', '&gt;' `
        -replace '"', '&quot;' `
        -replace "'", '&#39;'
}

function New-DonutSvg {
    param([int]$Score, [int]$Size = 130)
    $circumference = [math]::Round(2 * [math]::PI * 54, 3)
    $dash = [math]::Round(($Score / 100.0) * $circumference, 3)
    $gap  = [math]::Round($circumference - $dash, 3)
    $colour = Get-ScoreColour -Score $Score
    $fontSize = if ($Size -ge 130) { 28 } else { 22 }
    return @"
<svg viewBox="0 0 130 130" width="$Size" height="$Size" class="donut" role="img" aria-label="Score $Score out of 100">
  <circle cx="65" cy="65" r="54" fill="none" stroke="#1a3547" stroke-width="12"/>
  <circle cx="65" cy="65" r="54" fill="none" stroke="$colour" stroke-width="12"
          stroke-dasharray="$dash $gap"
          transform="rotate(-90 65 65)"
          stroke-linecap="round"/>
  <text x="65" y="73" text-anchor="middle" fill="#ffffff" font-size="$fontSize" font-weight="700" font-family="Inter, system-ui, sans-serif">$Score</text>
</svg>
"@
}

function Get-StatusClass {
    param([string]$Status)
    switch ($Status) {
        'Pass'    { 'pass' }
        'Warning' { 'warn' }
        'Fail'    { 'fail' }
        'Info'    { 'info' }
    }
}

function Get-StatusSymbol {
    param([string]$Status)
    switch ($Status) {
        'Pass'    { "&#10003; Pass" }      # ✓
        'Warning' { "&#9888; Warning" }    # ⚠
        'Fail'    { "&#10007; Fail" }      # ✗
        'Info'    { "&#9432; Info" }       # ⓘ
    }
}

function Assert-RequiredModules {
    $missing = @()
    foreach ($mod in $script:RequiredModules) {
        if (-not (Get-Module -ListAvailable -Name $mod)) {
            $missing += $mod
        }
    }
    if ($missing.Count -gt 0) {
        Write-Host ''
        Write-Host '  ERROR: Required PowerShell module(s) not installed:' -ForegroundColor Red
        foreach ($m in $missing) { Write-Host "    - $m" -ForegroundColor Red }
        Write-Host ''
        Write-Host '  Install with:' -ForegroundColor Yellow
        Write-Host ("    Install-Module {0} -Scope CurrentUser" -f ($missing -join ', ')) -ForegroundColor Yellow
        Write-Host ''
        throw 'Missing required modules.'
    }
    foreach ($mod in $script:RequiredModules) {
        Import-Module $mod -ErrorAction Stop | Out-Null
    }
}

# ==============================================================================
# DRY-RUN SEEDER (hidden; for HTML layout verification only)
# ==============================================================================

function Initialize-DryRunData {
    Write-Host ''
    Write-Host '  [DryRun] Seeding synthetic data. No Azure calls will be made.' -ForegroundColor Cyan

    $script:Context = [PSCustomObject]@{
        SubscriptionName = 'Contoso Production (DryRun)'
        SubscriptionId   = '00000000-0000-0000-0000-000000000000'
        TenantId         = '11111111-1111-1111-1111-111111111111'
    }
    $script:HostPoolCount    = 5
    $script:SessionHostCount = 47
    $script:ScalingPlanCount = 3
    $script:VmCount          = 47

    # v2 data sources - empty initialisations so PE check functions can read
    # them without null-ref errors. Real synthetic values get populated by the
    # PE check PRs that introduce each new check.
    $script:vmNics            = @{}
    $script:vmOsDisks         = @{}
    $script:fslogixDiscovery  = @{}
    $script:securityPricings  = @()
    $script:privateEndpoints  = @()
    $script:activityLogAlerts = @()
    $script:NicFetchFailed             = $false
    $script:DiskFetchFailed            = $false
    $script:StorageFetchFailed         = $false
    $script:SecurityPricingFetchFailed = $false
    $script:PrivateEndpointFetchFailed = $false
    $script:ActivityAlertFetchFailed   = $false

    # Each entry below seeds one synthetic check result. Name / Remediation /
    # LearnMore come from $script:CheckCatalog so the dry-run report stays in
    # lock-step with the canonical text used by the real check functions.

    Write-Section 'Cost Optimisation'
    $m = Get-Check 'ScalingPlanCoverage'
    Add-CheckResult -Category Cost -CheckName $m.Name -Status Fail -Score 40 `
        -Finding '2 of 5 pooled host pool(s) have a scaling plan assigned. Uncovered: hp-prod-pooled-02, hp-prod-pooled-04, hp-dev-pooled-01.' `
        -Remediation $m.Remediation -LearnMore $m.LearnMore

    $m = Get-Check 'StartVmOnConnect'
    Add-CheckResult -Category Cost -CheckName $m.Name -Status Warning -Score 40 `
        -Finding '1 of 2 personal host pool(s) have Start VM on Connect disabled: hp-personal-exec.' `
        -Remediation $m.Remediation -LearnMore $m.LearnMore

    $m = Get-Check 'UnhealthyHostsInRotation'
    Add-CheckResult -Category Cost -CheckName $m.Name -Status Pass -Score 100 `
        -Finding 'No unhealthy session hosts are accepting new sessions.' `
        -Remediation '' -LearnMore $m.LearnMore

    $m = Get-Check 'MaxSessionLimit'
    Add-CheckResult -Category Cost -CheckName $m.Name -Status Warning -Score 50 `
        -Finding '1 pooled host pool is at the default session limit (999999): hp-dev-pooled-01.' `
        -Remediation $m.Remediation -LearnMore $m.LearnMore

    Write-Section 'Reliability & Resilience'
    $m = Get-Check 'SessionHostHealth'
    Add-CheckResult -Category Reliability -CheckName $m.Name -Status Fail -Score 80 `
        -Finding '8 of 10 session hosts healthy (80%). Unhealthy: 2 Unavailable.' `
        -Remediation $m.Remediation -LearnMore $m.LearnMore

    $m = Get-Check 'RdpShortpath'
    Add-CheckResult -Category Reliability -CheckName $m.Name -Status Warning -Score 50 `
        -Finding '3 of 5 host pool(s) are missing explicit networkautodetect / bandwidthautodetect RDP properties.' `
        -Remediation $m.Remediation -LearnMore $m.LearnMore

    $m = Get-Check 'AgentUpdateRing'
    Add-CheckResult -Category Reliability -CheckName $m.Name -Status Pass -Score 100 `
        -Finding '1 host pool(s) in Validation ring, 4 in production ring. Good separation.' `
        -Remediation '' -LearnMore $m.LearnMore

    $m = Get-Check 'SessionCapacityHeadroom'
    Add-CheckResult -Category Reliability -CheckName $m.Name -Status Pass -Score 100 `
        -Finding 'All pooled host pools are below 85% session capacity utilisation.' `
        -Remediation '' -LearnMore $m.LearnMore

    $m = Get-Check 'FSLogixProfileRedundancy'
    Add-CheckResult -Category Reliability -CheckName $m.Name -Status Warning -Score 33 `
        -Finding '2 of 3 FSLogix-linked host pool(s) use non-zone-redundant storage (33% zone-redundant). Non-ZR: hp-prod-pooled-01 (storage stfslogixprod, SKU Standard_LRS); hp-dev-pooled-01 (storage stfslogixdev, SKU Standard_LRS).' `
        -Remediation $m.Remediation -LearnMore $m.LearnMore

    $m = Get-Check 'AvailabilityZoneDistribution'
    Add-CheckResult -Category Reliability -CheckName $m.Name -Status Warning -Score 50 `
        -Finding '1 of 2 multi-host pool(s) span >=2 availability zones (50%). Single-AZ pools: hp-prod-pooled-02 (all in zone 1).' `
        -Remediation $m.Remediation -LearnMore $m.LearnMore

    Write-Section 'Security Posture'
    $m = Get-Check 'DriveRedirection'
    Add-CheckResult -Category Security -CheckName $m.Name -Status Warning -Score 40 `
        -Finding '2 host pool(s) allow broad drive redirection (drivestoredirect:s:* or unset): hp-prod-pooled-01, hp-dev-pooled-01.' `
        -Remediation $m.Remediation -LearnMore $m.LearnMore

    $m = Get-Check 'ClipboardRedirection'
    Add-CheckResult -Category Security -CheckName $m.Name -Status Info -Score 100 `
        -Finding '4 host pool(s) have clipboard redirection enabled (or at default). This is common but should be a deliberate decision.' `
        -Remediation $m.Remediation -LearnMore $m.LearnMore

    $m = Get-Check 'TrustedLaunch'
    Add-CheckResult -Category Security -CheckName $m.Name -Status Warning -Score 60 `
        -Finding '3 of 5 session host VMs are using Trusted Launch. 2 VMs lack Secure Boot / vTPM protection.' `
        -Remediation $m.Remediation -LearnMore $m.LearnMore

    $m = Get-Check 'EntraIdJoin'
    Add-CheckResult -Category Security -CheckName $m.Name -Status Info -Score 100 `
        -Finding '3 of 5 session host VM(s) appear to be hybrid-joined or domain-joined only (AADLoginForWindows extension not detected).' `
        -Remediation $m.Remediation -LearnMore $m.LearnMore

    $m = Get-Check 'DefenderForCloudCoverage'
    Add-CheckResult -Category Security -CheckName $m.Name -Status Warning -Score 60 `
        -Finding 'Defender for Cloud coverage is incomplete on this subscription. Free / unconfigured plans: StorageAccounts: Free.' `
        -Remediation $m.Remediation -LearnMore $m.LearnMore

    $m = Get-Check 'AvdPrivateLink'
    Add-CheckResult -Category Security -CheckName $m.Name -Status Warning -Score 60 `
        -Finding '2 of 5 host pool(s) are exposed to public network access without a private endpoint (60% covered). Exposed: hp-prod-pooled-01 (PublicNetworkAccess: Enabled); hp-dev-pooled-01 (PublicNetworkAccess: Enabled).' `
        -Remediation $m.Remediation -LearnMore $m.LearnMore

    Write-Section 'Operational Excellence'
    $m = Get-Check 'DiagnosticSettings'
    Add-CheckResult -Category Operations -CheckName $m.Name -Status Fail -Score 40 `
        -Finding '2 of 5 host pool(s) have no diagnostic settings configured: hp-dev-pooled-01, hp-personal-exec, hp-prod-pooled-02.' `
        -Remediation $m.Remediation -LearnMore $m.LearnMore

    $m = Get-Check 'ResourceTagging'
    Add-CheckResult -Category Operations -CheckName $m.Name -Status Warning -Score 60 `
        -Finding '2 of 5 host pool(s) are missing Environment or Owner tags: hp-dev-pooled-01, hp-test-01.' `
        -Remediation $m.Remediation -LearnMore $m.LearnMore

    $m = Get-Check 'AgentUpdateState'
    Add-CheckResult -Category Operations -CheckName $m.Name -Status Pass -Score 100 `
        -Finding 'All session hosts have a healthy agent update state.' `
        -Remediation '' -LearnMore $m.LearnMore

    $m = Get-Check 'ServiceHealthAlerts'
    Add-CheckResult -Category Operations -CheckName $m.Name -Status Warning -Score 40 `
        -Finding 'No Service Health alerts cover Azure Virtual Desktop. 3 activity log alert rule(s) exist on this subscription, but none cover Azure Virtual Desktop Service Health events. There is no proactive notification channel for planned maintenance, service issues, or health advisories from Microsoft.' `
        -Remediation $m.Remediation -LearnMore $m.LearnMore

    $m = Get-Check 'LoadBalancingAlgorithm'
    Add-CheckResult -Category Operations -CheckName $m.Name -Status Pass -Score 100 `
        -Finding '3 pool(s) use BreadthFirst (performance-optimised), 1 pool(s) use DepthFirst (cost-optimised).' `
        -Remediation $m.Remediation -LearnMore $m.LearnMore

    Write-Section 'Performance Efficiency'
    $m = Get-Check 'AcceleratedNetworking'
    Add-CheckResult -Category Performance -CheckName $m.Name -Status Warning -Score 60 `
        -Finding '3 of 5 session host NIC(s) have Accelerated Networking enabled (60%). Disabled on: avd-prod-vm-04, avd-prod-vm-05.' `
        -Remediation $m.Remediation -LearnMore $m.LearnMore

    $m = Get-Check 'PremiumOsDisk'
    Add-CheckResult -Category Performance -CheckName $m.Name -Status Warning -Score 67 `
        -Finding '2 of 3 multi-session host OS disk(s) are Premium SSD or better (67%). Sub-premium: avd-prod-vm-05 (StandardSSD_LRS).' `
        -Remediation $m.Remediation -LearnMore $m.LearnMore

    $m = Get-Check 'Gen2VirtualMachines'
    Add-CheckResult -Category Performance -CheckName $m.Name -Status Pass -Score 100 `
        -Finding 'All 5 session host(s) are Gen2 VMs.' `
        -Remediation '' -LearnMore $m.LearnMore

    $m = Get-Check 'FSLogixRegionColocation'
    Add-CheckResult -Category Performance -CheckName $m.Name -Status Warning -Score 67 `
        -Finding '1 of 3 host pool(s) have FSLogix storage in a different region (67% colocated). Cross-region: hp-dev-pooled-01 (uksouth pool / ukwest storage). Discovery method: Tag: 2, Pattern: 1.' `
        -Remediation $m.Remediation -LearnMore $m.LearnMore
}

# ==============================================================================
# AZURE CONNECTION
# ==============================================================================

function Connect-ToAzure {
    Write-Section 'Connecting to Azure'
    if (-not $UseExistingConnection) {
        $connectArgs = @{}
        if ($SubscriptionId) { $connectArgs['Subscription'] = $SubscriptionId }
        if ($TenantId)       { $connectArgs['Tenant']       = $TenantId }
        try {
            Connect-AzAccount @connectArgs -WarningAction SilentlyContinue | Out-Null
        } catch {
            throw "Failed to connect to Azure: $($_.Exception.Message)"
        }
    }

    if ($SubscriptionId) {
        try {
            Set-AzContext -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
        } catch {
            throw "Failed to set subscription context to '$SubscriptionId': $($_.Exception.Message)"
        }
    }

    $ctx = Get-AzContext
    if (-not $ctx -or -not $ctx.Subscription) {
        throw 'No active Azure context. Run Connect-AzAccount or omit -UseExistingConnection.'
    }

    $script:Context = [PSCustomObject]@{
        SubscriptionName = $ctx.Subscription.Name
        SubscriptionId   = $ctx.Subscription.Id
        TenantId         = $ctx.Tenant.Id
    }

    Write-Host ('  Subscription : {0} ({1})' -f $ctx.Subscription.Name, $ctx.Subscription.Id) -ForegroundColor Gray
    Write-Host ('  Tenant       : {0}'       -f $ctx.Tenant.Id) -ForegroundColor Gray
}

# ==============================================================================
# DATA COLLECTION
# ==============================================================================

function Get-AvdEnvironmentData {
    Write-Section 'Collecting environment data'

    $script:allHostPools      = @()
    $script:allSessionHosts   = @()
    $script:allScalingPlans   = @()
    $script:allVMs            = @()
    $script:diagnosticSettings = @{}
    $script:hostPoolTags      = @{}
    $script:vmNics                  = @{}
    $script:vmOsDisks               = @{}
    $script:fslogixDiscovery        = @{}
    $script:securityPricings        = @()
    $script:privateEndpoints        = @()
    $script:activityLogAlerts       = @()
    $script:VmFetchFailed     = $false
    $script:DiagFetchFailed   = $false
    $script:TagFetchFailed    = $false
    $script:NicFetchFailed            = $false
    $script:DiskFetchFailed           = $false
    $script:StorageFetchFailed        = $false
    $script:SecurityPricingFetchFailed = $false
    $script:PrivateEndpointFetchFailed = $false
    $script:ActivityAlertFetchFailed   = $false

    # Host pools
    try {
        if ($HostPoolName -and $ResourceGroupName) {
            Write-Host '  Fetching host pool...            ' -NoNewline
            $script:allHostPools = @(Invoke-WithRetry -OperationName 'Get-AzWvdHostPool' -ScriptBlock {
                Get-AzWvdHostPool -ResourceGroupName $ResourceGroupName -Name $HostPoolName
            })
        } elseif ($ResourceGroupName) {
            Write-Host '  Fetching host pools...           ' -NoNewline
            $script:allHostPools = @(Invoke-WithRetry -OperationName 'Get-AzWvdHostPool' -ScriptBlock {
                Get-AzWvdHostPool -ResourceGroupName $ResourceGroupName
            })
        } else {
            Write-Host '  Fetching host pools...           ' -NoNewline
            $script:allHostPools = @(Invoke-WithRetry -OperationName 'Get-AzWvdHostPool' -ScriptBlock {
                Get-AzWvdHostPool
            })
        }
        Write-Host ("Found {0} host pool(s)" -f $script:allHostPools.Count) -ForegroundColor Green
    } catch {
        Write-Host 'FAILED' -ForegroundColor Red
        throw "Unable to list host pools: $($_.Exception.Message)"
    }

    $script:HostPoolCount = $script:allHostPools.Count
    if ($script:HostPoolCount -eq 0) {
        Write-Host ''
        Write-Host '  No AVD host pools found in the specified scope. Nothing to assess.' -ForegroundColor Yellow
        return $false
    }

    # Session hosts
    Write-Host '  Fetching session hosts...        ' -NoNewline
    $shList = [System.Collections.Generic.List[object]]::new()
    foreach ($hp in $script:allHostPools) {
        $hpRg   = Get-RgFromArmId -ResourceId $hp.Id
        $hpName = $hp.Name
        try {
            $hosts = @(Invoke-WithRetry -OperationName "Get-AzWvdSessionHost ($hpName)" -ScriptBlock {
                Get-AzWvdSessionHost -ResourceGroupName $hpRg -HostPoolName $hpName -ErrorAction Stop
            })
            foreach ($h in $hosts) {
                $h | Add-Member -NotePropertyName '_HostPoolName'       -NotePropertyValue $hpName      -Force
                $h | Add-Member -NotePropertyName '_HostPoolResourceId' -NotePropertyValue $hp.Id       -Force
                $h | Add-Member -NotePropertyName '_HostPoolType'       -NotePropertyValue $hp.HostPoolType -Force
                $shList.Add($h)
            }
        } catch {
            Write-Verbose "Session host fetch for $hpName failed: $($_.Exception.Message)"
        }
    }
    $script:allSessionHosts   = $shList.ToArray()
    $script:SessionHostCount  = $script:allSessionHosts.Count
    Write-Host ("Found {0} session host(s)" -f $script:SessionHostCount) -ForegroundColor Green

    # Scaling plans
    Write-Host '  Fetching scaling plans...        ' -NoNewline
    try {
        if ($ResourceGroupName) {
            $script:allScalingPlans = @(Invoke-WithRetry -OperationName 'Get-AzWvdScalingPlan' -ScriptBlock {
                Get-AzWvdScalingPlan -ResourceGroupName $ResourceGroupName -ErrorAction Stop
            })
        } else {
            $script:allScalingPlans = @(Invoke-WithRetry -OperationName 'Get-AzWvdScalingPlan' -ScriptBlock {
                Get-AzWvdScalingPlan -ErrorAction Stop
            })
        }
        Write-Host ("Found {0} scaling plan(s)" -f $script:allScalingPlans.Count) -ForegroundColor Green
    } catch {
        $script:allScalingPlans = @()
        Write-Host 'FAILED (continuing)' -ForegroundColor Yellow
    }
    $script:ScalingPlanCount = $script:allScalingPlans.Count

    # VMs
    Write-Host '  Fetching virtual machines...     ' -NoNewline
    $vmList = [System.Collections.Generic.List[object]]::new()
    try {
        $uniqueVmIds = $script:allSessionHosts.ResourceId | Where-Object { $_ } | Select-Object -Unique
        foreach ($vmId in $uniqueVmIds) {
            $parts = $vmId -split '/'
            if ($parts.Count -lt 9) { continue }
            $vmRg   = Get-RgFromArmId -ResourceId $vmId
            $vmName = $parts[-1]
            try {
                $vm = Invoke-WithRetry -OperationName "Get-AzVM ($vmName)" -ScriptBlock {
                    Get-AzVM -ResourceGroupName $vmRg -Name $vmName -Status -ErrorAction Stop
                }
                if ($vm) { $vmList.Add($vm) }
            } catch {
                Write-Verbose "VM fetch failed for $vmId : $($_.Exception.Message)"
            }
        }
        $script:allVMs = $vmList.ToArray()
        Write-Host ("Found {0} AVD virtual machine(s)" -f $script:allVMs.Count) -ForegroundColor Green
    } catch {
        $script:VmFetchFailed = $true
        $script:allVMs = @()
        Write-Host 'FAILED (continuing - VM checks will return Info)' -ForegroundColor Yellow
    }
    if ($script:allSessionHosts.Count -gt 0 -and $script:allVMs.Count -eq 0) {
        $script:VmFetchFailed = $true
    }
    $script:VmCount = $script:allVMs.Count

    # Diagnostic settings
    Write-Host '  Fetching diagnostic settings...  ' -NoNewline
    $diagOk = 0
    foreach ($hp in $script:allHostPools) {
        try {
            $ds = @(Invoke-WithRetry -OperationName "Get-AzDiagnosticSetting ($($hp.Name))" -ScriptBlock {
                Get-AzDiagnosticSetting -ResourceId $hp.Id -ErrorAction Stop
            })
            $script:diagnosticSettings[$hp.Id] = $ds
            $diagOk++
        } catch {
            $script:diagnosticSettings[$hp.Id] = $null
        }
    }
    if ($diagOk -eq 0 -and $script:allHostPools.Count -gt 0) {
        $script:DiagFetchFailed = $true
        Write-Host 'Permission denied (Diagnostic check will return Info)' -ForegroundColor Yellow
    } else {
        Write-Host 'Done' -ForegroundColor Green
    }

    # Tags. Prefer the inline $hp.Tag property when present (saves one ARM call
    # per host pool) and fall back to Get-AzResource only when it's null/missing,
    # since Az.DesktopVirtualization output has historically been inconsistent on
    # whether tags are populated inline.
    Write-Host '  Fetching resource tags...        ' -NoNewline
    $tagOk = 0
    foreach ($hp in $script:allHostPools) {
        $tags = $hp.Tag
        if (-not $tags -or $tags.Count -eq 0) {
            try {
                $res = Invoke-WithRetry -OperationName "Get-AzResource ($($hp.Name))" -ScriptBlock {
                    Get-AzResource -ResourceId $hp.Id -ErrorAction Stop
                }
                $tags = $res.Tags
            } catch {
                $tags = $null
            }
        }
        $script:hostPoolTags[$hp.Id] = $tags
        if ($null -ne $tags) { $tagOk++ }
    }
    if ($tagOk -eq 0 -and $script:allHostPools.Count -gt 0) {
        $script:TagFetchFailed = $true
        Write-Host 'Permission denied (Tag check will return Info)' -ForegroundColor Yellow
    } else {
        Write-Host 'Done' -ForegroundColor Green
    }

    # --------------------------------------------------------------------------
    # v2 data sources (Performance Efficiency + new checks across pillars)
    # Each fetch is additive and degrades only its dependent checks to Info on
    # failure - existing v1 checks never read these collections.
    # --------------------------------------------------------------------------

    # NICs (PE1: Accelerated Networking)
    Write-Host '  Fetching NICs...                 ' -NoNewline
    $nicOk = 0
    if ($script:allVMs.Count -gt 0) {
        foreach ($vm in $script:allVMs) {
            $nicRef = $null
            if ($vm.NetworkProfile -and $vm.NetworkProfile.NetworkInterfaces) {
                $nicRef = @($vm.NetworkProfile.NetworkInterfaces)[0]
            }
            if (-not $nicRef -or -not $nicRef.Id) { continue }
            try {
                $nic = Invoke-WithRetry -OperationName "Get-AzNetworkInterface ($($vm.Name))" -ScriptBlock {
                    Get-AzNetworkInterface -ResourceId $nicRef.Id -ErrorAction Stop
                }
                if ($nic) {
                    $script:vmNics[$vm.Id] = $nic
                    $nicOk++
                }
            } catch {
                Write-Verbose "NIC fetch failed for $($vm.Name): $($_.Exception.Message)"
            }
        }
    }
    if ($script:allVMs.Count -gt 0 -and $nicOk -eq 0) {
        $script:NicFetchFailed = $true
        Write-Host 'Permission denied (Accelerated Networking check will return Info)' -ForegroundColor Yellow
    } else {
        Write-Host ("Found {0} NIC(s)" -f $nicOk) -ForegroundColor Green
    }

    # OS disks (PE2: disk SKU; PE3: VM generation)
    Write-Host '  Fetching OS disks...             ' -NoNewline
    $diskOk = 0
    if ($script:allVMs.Count -gt 0) {
        foreach ($vm in $script:allVMs) {
            $diskId = $null
            if ($vm.StorageProfile -and $vm.StorageProfile.OsDisk -and $vm.StorageProfile.OsDisk.ManagedDisk) {
                $diskId = $vm.StorageProfile.OsDisk.ManagedDisk.Id
            }
            if (-not $diskId) { continue }
            try {
                $disk = Invoke-WithRetry -OperationName "Get-AzDisk ($($vm.Name))" -ScriptBlock {
                    Get-AzDisk -ResourceId $diskId -ErrorAction Stop
                }
                if ($disk) {
                    $script:vmOsDisks[$vm.Id] = $disk
                    $diskOk++
                }
            } catch {
                Write-Verbose "OS disk fetch failed for $($vm.Name): $($_.Exception.Message)"
            }
        }
    }
    if ($script:allVMs.Count -gt 0 -and $diskOk -eq 0) {
        $script:DiskFetchFailed = $true
        Write-Host 'Permission denied (Disk SKU / Gen2 checks will return Info)' -ForegroundColor Yellow
    } else {
        Write-Host ("Found {0} disk(s)" -f $diskOk) -ForegroundColor Green
    }

    # FSLogix storage discovery (PE4: region colocation; R6: profile redundancy)
    # Three-stage: explicit param override -> host pool tag -> name-pattern scan.
    Write-Host '  Discovering FSLogix storage...   ' -NoNewline
    $fslogixHits = 0
    $rgStorageCache = @{}  # cache per-RG storage lookups to avoid duplicate ARM calls
    foreach ($hp in $script:allHostPools) {
        $discovered = [PSCustomObject]@{
            StorageAccount = $null
            Method         = 'None'
        }
        $targetName = $null

        # Stage 1: explicit parameter override (applies to every host pool)
        if ($FSLogixStorageAccount) {
            $targetName = $FSLogixStorageAccount
            $discovered.Method = 'Override'
        }
        # Stage 2: host pool tag
        elseif ($script:hostPoolTags[$hp.Id]) {
            $tags = $script:hostPoolTags[$hp.Id]
            if ($tags.ContainsKey($FSLogixTagName) -and $tags[$FSLogixTagName]) {
                $targetName = $tags[$FSLogixTagName]
                $discovered.Method = 'Tag'
            }
        }

        # Stage 3: name-pattern scan within the host pool's RG
        if (-not $targetName -and $FSLogixNamePattern) {
            $hpRg = Get-RgFromArmId -ResourceId $hp.Id
            if (-not $rgStorageCache.ContainsKey($hpRg)) {
                try {
                    $rgStorageCache[$hpRg] = @(Invoke-WithRetry -OperationName "Get-AzStorageAccount ($hpRg)" -ScriptBlock {
                        Get-AzStorageAccount -ResourceGroupName $hpRg -ErrorAction Stop
                    })
                } catch {
                    $rgStorageCache[$hpRg] = $null  # null = fetch failed
                }
            }
            $rgStorage = $rgStorageCache[$hpRg]
            if ($null -ne $rgStorage) {
                $match = @($rgStorage | Where-Object { $_.StorageAccountName -like $FSLogixNamePattern }) | Select-Object -First 1
                if ($match) {
                    $discovered.StorageAccount = $match
                    $discovered.Method = 'Pattern'
                }
            }
        }

        # Stages 1/2 returned a name - resolve it to a storage account object.
        if ($targetName -and -not $discovered.StorageAccount) {
            $hpRg = Get-RgFromArmId -ResourceId $hp.Id
            try {
                $sa = Invoke-WithRetry -OperationName "Get-AzStorageAccount ($targetName)" -ScriptBlock {
                    # Try the host pool's RG first, fall back to sub-wide lookup
                    Get-AzStorageAccount -ResourceGroupName $hpRg -Name $targetName -ErrorAction Stop
                }
                if ($sa) { $discovered.StorageAccount = $sa }
            } catch {
                # Fallback: sub-wide scan (slower but handles cross-RG storage)
                try {
                    $all = Invoke-WithRetry -OperationName "Get-AzStorageAccount (sub-wide)" -ScriptBlock {
                        Get-AzStorageAccount -ErrorAction Stop
                    }
                    $match = @($all | Where-Object { $_.StorageAccountName -eq $targetName }) | Select-Object -First 1
                    if ($match) { $discovered.StorageAccount = $match }
                } catch {
                    Write-Verbose "FSLogix storage lookup failed for ${targetName}: $($_.Exception.Message)"
                }
            }
        }

        $script:fslogixDiscovery[$hp.Id] = $discovered
        if ($discovered.StorageAccount) { $fslogixHits++ }
    }

    # StorageFetchFailed flag fires only if every RG's storage list failed - a
    # blanket permissions problem, not a "couldn't find FSLogix" outcome.
    $storageRgFailures = @($rgStorageCache.Values | Where-Object { $null -eq $_ }).Count
    if ($rgStorageCache.Count -gt 0 -and $storageRgFailures -eq $rgStorageCache.Count) {
        $script:StorageFetchFailed = $true
        Write-Host 'Permission denied (FSLogix checks will return Info)' -ForegroundColor Yellow
    } elseif ($fslogixHits -eq 0 -and -not $FSLogixStorageAccount) {
        Write-Host 'No FSLogix storage auto-discovered (Info-level finding)' -ForegroundColor Yellow
    } else {
        Write-Host ("Linked {0} host pool(s) to FSLogix storage" -f $fslogixHits) -ForegroundColor Green
    }

    # Defender for Cloud pricing (S5)
    Write-Host '  Fetching Defender pricing...     ' -NoNewline
    try {
        $script:securityPricings = @(Invoke-WithRetry -OperationName 'Get-AzSecurityPricing' -ScriptBlock {
            Get-AzSecurityPricing -ErrorAction Stop
        })
        Write-Host ("Found {0} pricing entry(ies)" -f $script:securityPricings.Count) -ForegroundColor Green
    } catch {
        $script:SecurityPricingFetchFailed = $true
        $script:securityPricings = @()
        Write-Host 'Permission denied (Defender check will return Info)' -ForegroundColor Yellow
    }

    # Private endpoints (S6) - subscription-wide is faster than per-RG and
    # avoids missing endpoints in RGs that don't host the host pool itself.
    Write-Host '  Fetching private endpoints...    ' -NoNewline
    try {
        $script:privateEndpoints = @(Invoke-WithRetry -OperationName 'Get-AzPrivateEndpoint' -ScriptBlock {
            Get-AzPrivateEndpoint -ErrorAction Stop
        })
        Write-Host ("Found {0} private endpoint(s)" -f $script:privateEndpoints.Count) -ForegroundColor Green
    } catch {
        $script:PrivateEndpointFetchFailed = $true
        $script:privateEndpoints = @()
        Write-Host 'Permission denied (Private Link check will return Info)' -ForegroundColor Yellow
    }

    # Activity log alerts (O5: Service Health alerts for AVD)
    Write-Host '  Fetching activity log alerts...  ' -NoNewline
    try {
        $script:activityLogAlerts = @(Invoke-WithRetry -OperationName 'Get-AzActivityLogAlert' -ScriptBlock {
            Get-AzActivityLogAlert -ErrorAction Stop
        })
        Write-Host ("Found {0} alert rule(s)" -f $script:activityLogAlerts.Count) -ForegroundColor Green
    } catch {
        $script:ActivityAlertFetchFailed = $true
        $script:activityLogAlerts = @()
        Write-Host 'Permission denied (Service Health alert check will return Info)' -ForegroundColor Yellow
    }

    $script:pooledHostPools   = @($script:allHostPools | Where-Object { $_.HostPoolType -eq 'Pooled' })
    $script:personalHostPools = @($script:allHostPools | Where-Object { $_.HostPoolType -eq 'Personal' })

    return $true
}

# ==============================================================================
# CHECKS: COST OPTIMISATION
# ==============================================================================

function Invoke-CostChecks {
    Write-Section 'Cost Optimisation'

    # Check 1: Scaling Plan Coverage
    $m = Get-Check 'ScalingPlanCoverage'
    if ($script:pooledHostPools.Count -eq 0) {
        Add-CheckResult -Category Cost -CheckName $m.Name -Status Info -Score 100 `
            -Finding 'No pooled host pools found. Scaling plans apply to pooled host pools only.' `
            -Remediation 'No action required.' `
            -LearnMore $m.LearnMore
    } else {
        $referencedIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($sp in $script:allScalingPlans) {
            foreach ($ref in @($sp.HostPoolReference)) {
                if ($ref -and $ref.HostPoolArmPath) {
                    [void]$referencedIds.Add($ref.HostPoolArmPath)
                }
            }
        }
        $covered   = @($script:pooledHostPools | Where-Object { $referencedIds.Contains($_.Id) })
        $uncovered = @($script:pooledHostPools | Where-Object { -not $referencedIds.Contains($_.Id) })
        if ($uncovered.Count -eq 0) {
            Add-CheckResult -Category Cost -CheckName $m.Name -Status Pass -Score 100 `
                -Finding ("All {0} pooled host pool(s) have a scaling plan configured." -f $script:pooledHostPools.Count) `
                -Remediation '' -LearnMore $m.LearnMore
        } else {
            $pct = [int][math]::Round(($covered.Count / $script:pooledHostPools.Count) * 100)
            $names = ($uncovered | ForEach-Object { $_.Name }) -join ', '
            Add-CheckResult -Category Cost -CheckName $m.Name -Status Fail -Score $pct `
                -Finding ("{0} of {1} pooled host pool(s) have a scaling plan. Uncovered: {2}." -f $covered.Count, $script:pooledHostPools.Count, $names) `
                -Remediation $m.Remediation -LearnMore $m.LearnMore
        }
    }

    # Check 2: Start VM on Connect (Personal)
    $m = Get-Check 'StartVmOnConnect'
    if ($script:personalHostPools.Count -eq 0) {
        Add-CheckResult -Category Cost -CheckName $m.Name -Status Info -Score 100 `
            -Finding 'No personal host pools found. Start VM on Connect applies to personal host pools.' `
            -Remediation 'No action required.' -LearnMore $m.LearnMore
    } else {
        $offPools = @($script:personalHostPools | Where-Object { -not $_.StartVMOnConnect })
        if ($offPools.Count -eq 0) {
            Add-CheckResult -Category Cost -CheckName $m.Name -Status Pass -Score 100 `
                -Finding ("All {0} personal host pool(s) have Start VM on Connect enabled." -f $script:personalHostPools.Count) `
                -Remediation '' -LearnMore $m.LearnMore
        } else {
            $names = ($offPools | ForEach-Object { $_.Name }) -join ', '
            Add-CheckResult -Category Cost -CheckName $m.Name -Status Warning -Score 40 `
                -Finding ("{0} of {1} personal host pool(s) have Start VM on Connect disabled: {2}." -f $offPools.Count, $script:personalHostPools.Count, $names) `
                -Remediation $m.Remediation -LearnMore $m.LearnMore
        }
    }

    # Check 3: Unhealthy hosts still in rotation
    $m = Get-Check 'UnhealthyHostsInRotation'
    $unhealthyStates = @('Unavailable','NeedsAssistance','UpgradeFailed','NoHeartbeat')
    $stillRotating = @($script:allSessionHosts | Where-Object {
        ($unhealthyStates -contains $_.Status) -and ($_.AllowNewSession -eq $true)
    })
    if ($stillRotating.Count -eq 0) {
        Add-CheckResult -Category Cost -CheckName $m.Name -Status Pass -Score 100 `
            -Finding 'No unhealthy session hosts are accepting new sessions.' `
            -Remediation '' -LearnMore $m.LearnMore
    } else {
        $names = ($stillRotating | ForEach-Object { ($_.Name -split '/')[-1] }) -join ', '
        Add-CheckResult -Category Cost -CheckName $m.Name -Status Warning -Score 30 `
            -Finding ("{0} unhealthy host(s) still accepting new sessions: {1}." -f $stillRotating.Count, $names) `
            -Remediation $m.Remediation -LearnMore $m.LearnMore
    }

    # Check 4: Max Session Limit
    $m = Get-Check 'MaxSessionLimit'
    if ($script:pooledHostPools.Count -eq 0) {
        Add-CheckResult -Category Cost -CheckName $m.Name -Status Info -Score 100 `
            -Finding 'No pooled host pools found. Max session limit applies to pooled host pools.' `
            -Remediation 'No action required.' -LearnMore $m.LearnMore
    } else {
        $bad = @($script:pooledHostPools | Where-Object { $_.MaxSessionLimit -ge 999999 -or $_.MaxSessionLimit -le 0 })
        if ($bad.Count -eq 0) {
            Add-CheckResult -Category Cost -CheckName $m.Name -Status Pass -Score 100 `
                -Finding ("All {0} pooled host pool(s) have a realistic max session limit." -f $script:pooledHostPools.Count) `
                -Remediation '' -LearnMore $m.LearnMore
        } else {
            $names = ($bad | ForEach-Object { $_.Name }) -join ', '
            Add-CheckResult -Category Cost -CheckName $m.Name -Status Warning -Score 50 `
                -Finding ("{0} pooled host pool(s) at the default or invalid session limit: {1}." -f $bad.Count, $names) `
                -Remediation $m.Remediation -LearnMore $m.LearnMore
        }
    }
}

# ==============================================================================
# CHECKS: RELIABILITY & RESILIENCE
# ==============================================================================

function Invoke-ReliabilityChecks {
    Write-Section 'Reliability & Resilience'

    # Check 5: Session host health
    $m = Get-Check 'SessionHostHealth'
    if ($script:allSessionHosts.Count -eq 0) {
        Add-CheckResult -Category Reliability -CheckName $m.Name -Status Info -Score 100 `
            -Finding 'No session hosts found across the assessed host pools.' `
            -Remediation 'Deploy session hosts into your host pool(s) to begin serving users.' `
            -LearnMore $m.LearnMore
    } else {
        $healthyStates = @('Available','Shutdown')
        $unhealthy = @($script:allSessionHosts | Where-Object { $healthyStates -notcontains $_.Status })
        if ($unhealthy.Count -eq 0) {
            Add-CheckResult -Category Reliability -CheckName $m.Name -Status Pass -Score 100 `
                -Finding ("All {0} session host(s) are healthy." -f $script:allSessionHosts.Count) `
                -Remediation '' -LearnMore $m.LearnMore
        } else {
            $healthyCount = $script:allSessionHosts.Count - $unhealthy.Count
            $pct = [int][math]::Round(($healthyCount / $script:allSessionHosts.Count) * 100)
            $breakdown = ($unhealthy | Group-Object Status | ForEach-Object { "$($_.Count) $($_.Name)" }) -join ', '
            Add-CheckResult -Category Reliability -CheckName $m.Name -Status Fail -Score $pct `
                -Finding ("{0} of {1} session host(s) healthy ({2}%). Unhealthy: {3}." -f $healthyCount, $script:allSessionHosts.Count, $pct, $breakdown) `
                -Remediation $m.Remediation -LearnMore $m.LearnMore
        }
    }

    # Check 6: RDP Shortpath / network auto-detect
    $m = Get-Check 'RdpShortpath'
    $missing = @($script:allHostPools | Where-Object {
        $nad = Get-RdpProperty -RdpString $_.CustomRdpProperty -PropertyName 'networkautodetect'
        $bad = Get-RdpProperty -RdpString $_.CustomRdpProperty -PropertyName 'bandwidthautodetect'
        ($nad -ne '1') -or ($bad -ne '1')
    })
    if ($missing.Count -eq 0) {
        Add-CheckResult -Category Reliability -CheckName $m.Name -Status Pass -Score 100 `
            -Finding ("All {0} host pool(s) have network auto-detect properties set for RDP Shortpath." -f $script:allHostPools.Count) `
            -Remediation '' -LearnMore $m.LearnMore
    } else {
        $names = ($missing | ForEach-Object { $_.Name }) -join ', '
        Add-CheckResult -Category Reliability -CheckName $m.Name -Status Warning -Score 50 `
            -Finding ("{0} of {1} host pool(s) missing explicit networkautodetect / bandwidthautodetect: {2}." -f $missing.Count, $script:allHostPools.Count, $names) `
            -Remediation $m.Remediation -LearnMore $m.LearnMore
    }

    # Check 7: Agent update ring
    $m = Get-Check 'AgentUpdateRing'
    $validationCount = @($script:allHostPools | Where-Object { $_.ValidationEnvironment -eq $true }).Count
    $total = $script:allHostPools.Count
    if ($validationCount -gt 0 -and $validationCount -lt $total) {
        Add-CheckResult -Category Reliability -CheckName $m.Name -Status Pass -Score 100 `
            -Finding ("{0} host pool(s) are in the Validation ring, {1} in production ring. Good separation." -f $validationCount, ($total - $validationCount)) `
            -Remediation '' -LearnMore $m.LearnMore
    } elseif ($validationCount -eq 0) {
        Add-CheckResult -Category Reliability -CheckName $m.Name -Status Warning -Score 70 `
            -Finding 'No host pools are on the validation ring. No early warning for AVD agent updates.' `
            -Remediation $m.Remediation -LearnMore $m.LearnMore
    } else {
        Add-CheckResult -Category Reliability -CheckName $m.Name -Status Warning -Score 40 `
            -Finding 'All host pools are on the Validation ring. Production users are receiving pre-release agent updates.' `
            -Remediation $m.RemediationAllValidation -LearnMore $m.LearnMore
    }

    # Check 8: Session capacity headroom
    $m = Get-Check 'SessionCapacityHeadroom'
    if ($script:pooledHostPools.Count -eq 0) {
        Add-CheckResult -Category Reliability -CheckName $m.Name -Status Info -Score 100 `
            -Finding 'No pooled host pools found. Capacity check applies to pooled host pools.' `
            -Remediation 'No action required.' -LearnMore $m.LearnMore
    } else {
        $overCapacity = [System.Collections.Generic.List[object]]::new()
        foreach ($hp in $script:pooledHostPools) {
            $hostsInPool = @($script:allSessionHosts | Where-Object { $_._HostPoolResourceId -eq $hp.Id })
            if ($hostsInPool.Count -eq 0) { continue }
            if ($hp.MaxSessionLimit -le 0 -or $hp.MaxSessionLimit -ge 999999) { continue }
            $total = ($hostsInPool | Measure-Object -Property Session -Sum).Sum
            if (-not $total) { $total = ($hostsInPool | Measure-Object -Property Sessions -Sum).Sum }
            if (-not $total) { $total = 0 }
            $capacity = $hp.MaxSessionLimit * $hostsInPool.Count
            if ($capacity -le 0) { continue }
            $util = $total / $capacity
            if ($util -gt 0.85) {
                $overCapacity.Add([PSCustomObject]@{ Name = $hp.Name; Pct = [int][math]::Round($util * 100) })
            }
        }
        if ($overCapacity.Count -eq 0) {
            Add-CheckResult -Category Reliability -CheckName $m.Name -Status Pass -Score 100 `
                -Finding 'All pooled host pools are below 85% session capacity utilisation.' `
                -Remediation '' -LearnMore $m.LearnMore
        } else {
            $detail = ($overCapacity | ForEach-Object { "$($_.Name) ($($_.Pct)%)" }) -join ', '
            Add-CheckResult -Category Reliability -CheckName $m.Name -Status Warning -Score 30 `
                -Finding ("{0} pool(s) over 85% capacity: {1}." -f $overCapacity.Count, $detail) `
                -Remediation $m.Remediation -LearnMore $m.LearnMore
        }
    }

    # Check R6: FSLogix Profile Redundancy (zone-redundant storage SKU)
    # Reuses the discovery data populated in Get-AvdEnvironmentData. ZRS, GZRS,
    # RA-GZRS, and Premium_ZRS replicate synchronously across three AZs - LRS
    # and GRS do not. Scoring is per host pool so storage shared across many
    # pools weights the score correctly.
    $m = Get-Check 'FSLogixProfileRedundancy'
    $zrSkus = @('Standard_ZRS','Standard_GZRS','Standard_RAGZRS','Premium_ZRS')
    $fslogixLinks = [System.Collections.Generic.List[object]]::new()
    foreach ($hp in $script:allHostPools) {
        $d = $script:fslogixDiscovery[$hp.Id]
        if ($d -and $d.StorageAccount) {
            $fslogixLinks.Add([PSCustomObject]@{
                HostPool       = $hp
                StorageAccount = $d.StorageAccount
                Method         = $d.Method
            })
        }
    }

    if ($script:StorageFetchFailed) {
        Add-CheckResult -Category Reliability -CheckName $m.Name -Status Info -Score 100 `
            -Finding 'Cannot evaluate FSLogix profile redundancy: storage account read access was denied on every resource group containing a host pool.' `
            -Remediation $m.Remediation -LearnMore $m.LearnMore
    } elseif ($fslogixLinks.Count -eq 0) {
        Add-CheckResult -Category Reliability -CheckName $m.Name -Status Info -Score 100 `
            -Finding "FSLogix storage could not be auto-discovered for any host pool. Re-run with -FSLogixStorageAccount <name> to override, tag a host pool with 'FSLogixStorageAccount' = <storage account name>, or ensure the FSLogix storage account name matches the -FSLogixNamePattern (default '*fslogix*')." `
            -Remediation $m.Remediation -LearnMore $m.LearnMore
    } else {
        $nonZr = [System.Collections.Generic.List[string]]::new()
        foreach ($link in $fslogixLinks) {
            $sku = $link.StorageAccount.Sku.Name
            if ($zrSkus -notcontains $sku) {
                $nonZr.Add(('{0} (storage {1}, SKU {2})' -f $link.HostPool.Name, $link.StorageAccount.StorageAccountName, $sku))
            }
        }
        if ($nonZr.Count -eq 0) {
            Add-CheckResult -Category Reliability -CheckName $m.Name -Status Pass -Score 100 `
                -Finding ("All {0} discovered FSLogix storage account(s) use a zone-redundant SKU (ZRS / GZRS / RAGZRS / Premium_ZRS)." -f $fslogixLinks.Count) `
                -Remediation '' -LearnMore $m.LearnMore
        } else {
            $ok  = $fslogixLinks.Count - $nonZr.Count
            $pct = [int][math]::Round(($ok / $fslogixLinks.Count) * 100)
            $shown = ($nonZr | Select-Object -First 5) -join '; '
            $more  = if ($nonZr.Count -gt 5) { (" (+{0} more)" -f ($nonZr.Count - 5)) } else { '' }
            $status = if ($pct -lt 50) { 'Fail' } else { 'Warning' }
            Add-CheckResult -Category Reliability -CheckName $m.Name -Status $status -Score $pct `
                -Finding ("{0} of {1} FSLogix-linked host pool(s) use non-zone-redundant storage ({2}% zone-redundant). Non-ZR: {3}{4}." -f $nonZr.Count, $fslogixLinks.Count, $pct, $shown, $more) `
                -Remediation $m.Remediation -LearnMore $m.LearnMore
        }
    }

    # Check R5: Availability Zone Distribution
    # Per pool: count distinct $vm.Zones values across the pool's VMs.
    # >=2 distinct zones = zone-distributed (Pass-worthy).
    # 1 distinct zone   = single-AZ risk (Warning-worthy).
    # 0 zone info       = either region does not support AZs, or VMs were not
    #                     deployed with explicit zone choice. Report as Info
    #                     context and exclude from scoring.
    # Only applies to pooled host pools with >=2 session hosts - single-host
    # pools cannot be zone-distributed by definition.
    $m = Get-Check 'AvailabilityZoneDistribution'
    $vmById = @{}
    foreach ($vm in $script:allVMs) { $vmById[$vm.Id] = $vm }

    if ($script:VmFetchFailed -or $script:allVMs.Count -eq 0) {
        Add-CheckResult -Category Reliability -CheckName $m.Name -Status Info -Score 100 `
            -Finding 'Cannot evaluate availability zone distribution: no VM data available.' `
            -Remediation $m.Remediation -LearnMore $m.LearnMore
    } else {
        $singleAz = [System.Collections.Generic.List[string]]::new()
        $noZoneInfo = [System.Collections.Generic.List[string]]::new()
        $distributed = 0
        $scorablePools = 0

        foreach ($hp in $script:pooledHostPools) {
            $hostsInPool = @($script:allSessionHosts | Where-Object { $_._HostPoolResourceId -eq $hp.Id })
            if ($hostsInPool.Count -lt 2) { continue }

            $zones = @()
            foreach ($sh in $hostsInPool) {
                $vm = $vmById[$sh.ResourceId]
                if ($vm -and $vm.Zones -and $vm.Zones.Count -gt 0 -and $vm.Zones[0]) {
                    $zones += $vm.Zones[0]
                }
            }
            $distinctZones = @($zones | Select-Object -Unique)

            if ($distinctZones.Count -eq 0) {
                $noZoneInfo.Add(('{0} ({1} host(s))' -f $hp.Name, $hostsInPool.Count))
            } elseif ($distinctZones.Count -eq 1) {
                $singleAz.Add(('{0} (all in zone {1})' -f $hp.Name, $distinctZones[0]))
                $scorablePools++
            } else {
                $distributed++
                $scorablePools++
            }
        }

        if ($scorablePools -eq 0 -and $noZoneInfo.Count -eq 0) {
            Add-CheckResult -Category Reliability -CheckName $m.Name -Status Info -Score 100 `
                -Finding 'No multi-host pooled host pools found. Availability zone distribution applies to pooled host pools with at least 2 session hosts.' `
                -Remediation 'No action required.' -LearnMore $m.LearnMore
        } elseif ($scorablePools -eq 0) {
            # All eligible pools have no zone info - either non-AZ region or
            # non-zonal deployment. Either way, report as Info because we
            # cannot tell which without a region capabilities lookup.
            $shown = ($noZoneInfo | Select-Object -First 5) -join '; '
            $more  = if ($noZoneInfo.Count -gt 5) { (" (+{0} more)" -f ($noZoneInfo.Count - 5)) } else { '' }
            Add-CheckResult -Category Reliability -CheckName $m.Name -Status Info -Score 100 `
                -Finding ("{0} multi-host pool(s) have no zone information on their VMs. Either the deployment region does not support availability zones, or the VMs were deployed without an explicit zone choice. Pools: {1}{2}." -f $noZoneInfo.Count, $shown, $more) `
                -Remediation $m.Remediation -LearnMore $m.LearnMore
        } elseif ($singleAz.Count -eq 0) {
            $tail = if ($noZoneInfo.Count -gt 0) { (" {0} pool(s) had no zone info and were excluded from scoring." -f $noZoneInfo.Count) } else { '' }
            Add-CheckResult -Category Reliability -CheckName $m.Name -Status Pass -Score 100 `
                -Finding ("All {0} multi-host pooled host pool(s) span at least 2 availability zones.{1}" -f $distributed, $tail) `
                -Remediation '' -LearnMore $m.LearnMore
        } else {
            $pct = [int][math]::Round(($distributed / $scorablePools) * 100)
            $shown = ($singleAz | Select-Object -First 5) -join '; '
            $more  = if ($singleAz.Count -gt 5) { (" (+{0} more)" -f ($singleAz.Count - 5)) } else { '' }
            $status = if ($pct -lt 50) { 'Fail' } else { 'Warning' }
            $tail   = if ($noZoneInfo.Count -gt 0) { (" {0} additional pool(s) had no zone info and were excluded from scoring." -f $noZoneInfo.Count) } else { '' }
            Add-CheckResult -Category Reliability -CheckName $m.Name -Status $status -Score $pct `
                -Finding ("{0} of {1} multi-host pool(s) span >=2 availability zones ({2}%). Single-AZ pools: {3}{4}.{5}" -f $distributed, $scorablePools, $pct, $shown, $more, $tail) `
                -Remediation $m.Remediation -LearnMore $m.LearnMore
        }
    }
}

# ==============================================================================
# CHECKS: SECURITY POSTURE
# ==============================================================================

function Invoke-SecurityChecks {
    Write-Section 'Security Posture'

    # Check 9: Drive redirection
    $m = Get-Check 'DriveRedirection'
    $risky = @($script:allHostPools | Where-Object {
        $v = Get-RdpProperty -RdpString $_.CustomRdpProperty -PropertyName 'drivestoredirect'
        ($null -eq $v) -or ($v -eq '*')
    })
    if ($risky.Count -eq 0) {
        Add-CheckResult -Category Security -CheckName $m.Name -Status Pass -Score 100 `
            -Finding ("All {0} host pool(s) have drive redirection explicitly restricted." -f $script:allHostPools.Count) `
            -Remediation '' -LearnMore $m.LearnMore
    } else {
        $names = ($risky | ForEach-Object { $_.Name }) -join ', '
        Add-CheckResult -Category Security -CheckName $m.Name -Status Warning -Score 40 `
            -Finding ("{0} host pool(s) allow broad drive redirection (drivestoredirect:s:* or unset): {1}." -f $risky.Count, $names) `
            -Remediation $m.Remediation -LearnMore $m.LearnMore
    }

    # Check 10: Clipboard redirection (always Info)
    $m = Get-Check 'ClipboardRedirection'
    $clip = @($script:allHostPools | Where-Object {
        $v = Get-RdpProperty -RdpString $_.CustomRdpProperty -PropertyName 'redirectclipboard'
        ($null -eq $v) -or ($v -eq '1')
    })
    if ($clip.Count -eq 0) {
        Add-CheckResult -Category Security -CheckName $m.Name -Status Pass -Score 100 `
            -Finding ("All {0} host pool(s) have clipboard redirection explicitly disabled." -f $script:allHostPools.Count) `
            -Remediation '' -LearnMore $m.LearnMore
    } else {
        Add-CheckResult -Category Security -CheckName $m.Name -Status Info -Score 100 `
            -Finding ("{0} host pool(s) have clipboard redirection enabled (or at default). This is common but should be a deliberate decision." -f $clip.Count) `
            -Remediation $m.Remediation -LearnMore $m.LearnMore
    }

    # Check 11: Trusted Launch
    $m = Get-Check 'TrustedLaunch'
    if ($script:VmFetchFailed -or $script:allVMs.Count -eq 0) {
        Add-CheckResult -Category Security -CheckName $m.Name -Status Info -Score 100 `
            -Finding 'Unable to retrieve VM data - Reader permissions may be missing on the compute resources. Skipping Trusted Launch check.' `
            -Remediation 'Grant the Reader role on the VM resource groups (or subscription) so AVD-Assess can read VM properties, then re-run.' `
            -LearnMore $m.LearnMore
    } else {
        $trusted = @($script:allVMs | Where-Object { $_.SecurityProfile -and $_.SecurityProfile.SecurityType -eq 'TrustedLaunch' })
        if ($trusted.Count -eq $script:allVMs.Count) {
            Add-CheckResult -Category Security -CheckName $m.Name -Status Pass -Score 100 `
                -Finding ("All {0} session host VM(s) are using Trusted Launch." -f $script:allVMs.Count) `
                -Remediation '' -LearnMore $m.LearnMore
        } else {
            $pct = [int][math]::Round(($trusted.Count / $script:allVMs.Count) * 100)
            Add-CheckResult -Category Security -CheckName $m.Name -Status Warning -Score $pct `
                -Finding ("{0} of {1} session host VM(s) using Trusted Launch ({2}%). Others lack Secure Boot / vTPM protection." -f $trusted.Count, $script:allVMs.Count, $pct) `
                -Remediation $m.Remediation -LearnMore $m.LearnMore
        }
    }

    # Check 12: Entra ID join (Info only)
    $m = Get-Check 'EntraIdJoin'
    if ($script:VmFetchFailed -or $script:allVMs.Count -eq 0) {
        Add-CheckResult -Category Security -CheckName $m.Name -Status Info -Score 100 `
            -Finding 'Unable to retrieve VM data - join status could not be evaluated.' `
            -Remediation 'Grant Reader access to the VM resource groups so AVD-Assess can inspect VM extensions.' `
            -LearnMore $m.LearnMore
    } else {
        $entra = @($script:allVMs | Where-Object {
            $exts = @($_.Extensions)
            ($exts | Where-Object { $_.Name -eq 'AADLoginForWindows' -or $_.VirtualMachineExtensionType -eq 'AADLoginForWindows' }).Count -gt 0
        })
        $other = $script:allVMs.Count - $entra.Count
        if ($other -eq 0) {
            Add-CheckResult -Category Security -CheckName $m.Name -Status Pass -Score 100 `
                -Finding ("All {0} session host VM(s) appear to be Entra ID joined." -f $script:allVMs.Count) `
                -Remediation '' -LearnMore $m.LearnMore
        } else {
            Add-CheckResult -Category Security -CheckName $m.Name -Status Info -Score 100 `
                -Finding ("{0} of {1} session host VM(s) appear to be hybrid-joined or domain-joined only (AADLoginForWindows extension not detected). Entra ID join is the recommended approach for new AVD deployments." -f $other, $script:allVMs.Count) `
                -Remediation $m.Remediation -LearnMore $m.LearnMore
        }
    }

    # Check S5: Defender for Cloud Coverage
    # WAF singles out VirtualMachines as the must-have plan (Defender for
    # Servers covers vuln assessment, FIM, JIT, adaptive app controls).
    # StorageAccounts is "ideally too" - matters for FSLogix profile shares
    # and app attach storage. Score = (VM standard ? 60 : 0) + (Storage standard ? 40 : 0).
    # VM weighted higher because it is the WAF requirement; storage is the bonus.
    $m = Get-Check 'DefenderForCloudCoverage'
    if ($script:SecurityPricingFetchFailed) {
        Add-CheckResult -Category Security -CheckName $m.Name -Status Info -Score 100 `
            -Finding 'Unable to read Defender for Cloud pricing - the current identity lacks Microsoft.Security/pricings/read on the subscription.' `
            -Remediation 'Grant Security Reader (or Reader on the Microsoft.Security namespace) on the subscription and re-run.' `
            -LearnMore $m.LearnMore
    } elseif ($script:securityPricings.Count -eq 0) {
        Add-CheckResult -Category Security -CheckName $m.Name -Status Info -Score 100 `
            -Finding 'Defender for Cloud pricing endpoint returned no entries. The subscription may have a non-standard configuration; verify Defender for Cloud is initialised.' `
            -Remediation $m.Remediation -LearnMore $m.LearnMore
    } else {
        $vmPricing = @($script:securityPricings | Where-Object { $_.Name -eq 'VirtualMachines' }) | Select-Object -First 1
        $storagePricing = @($script:securityPricings | Where-Object { $_.Name -eq 'StorageAccounts' }) | Select-Object -First 1
        $vmStandard      = $vmPricing      -and $vmPricing.PricingTier      -ne 'Free'
        $storageStandard = $storagePricing -and $storagePricing.PricingTier -ne 'Free'
        $score = (& { if ($vmStandard) { 60 } else { 0 } }) + (& { if ($storageStandard) { 40 } else { 0 } })

        $vmTier      = if ($vmPricing)      { $vmPricing.PricingTier }      else { 'not configured' }
        $storageTier = if ($storagePricing) { $storagePricing.PricingTier } else { 'not configured' }

        if ($vmStandard -and $storageStandard) {
            Add-CheckResult -Category Security -CheckName $m.Name -Status Pass -Score 100 `
                -Finding ("Defender for Servers and Defender for Storage are both on Standard tier (VirtualMachines: {0}, StorageAccounts: {1})." -f $vmTier, $storageTier) `
                -Remediation '' -LearnMore $m.LearnMore
        } else {
            $gaps = [System.Collections.Generic.List[string]]::new()
            if (-not $vmStandard)      { $gaps.Add(('VirtualMachines: {0}'  -f $vmTier)) }
            if (-not $storageStandard) { $gaps.Add(('StorageAccounts: {0}' -f $storageTier)) }
            $status = if (-not $vmStandard) { 'Fail' } else { 'Warning' }
            Add-CheckResult -Category Security -CheckName $m.Name -Status $status -Score $score `
                -Finding ("Defender for Cloud coverage is incomplete on this subscription. Free / unconfigured plans: {0}." -f ($gaps -join '; ')) `
                -Remediation $m.Remediation -LearnMore $m.LearnMore
        }
    }

    # Check S6: AVD Private Link
    # Per host pool: PublicNetworkAccess = Disabled is a clean pass.
    # If Enabled (or one of the partial states), the host pool must be
    # fronted by a Private Endpoint - matched by walking PE connections
    # and looking for one whose PrivateLinkServiceId points at the host
    # pool. AVD's PE target ID is the host pool's ARM ID, sometimes with
    # a /connection/<name> suffix, so we use a starts-with match.
    # Older Az.DesktopVirtualization versions do not surface
    # PublicNetworkAccess - degrade to Info in that case so the check
    # does not produce false warnings.
    $m = Get-Check 'AvdPrivateLink'
    if ($script:PrivateEndpointFetchFailed) {
        Add-CheckResult -Category Security -CheckName $m.Name -Status Info -Score 100 `
            -Finding 'Unable to enumerate private endpoints - the current identity lacks Microsoft.Network/privateEndpoints/read on the subscription.' `
            -Remediation 'Grant Reader on the subscription (or on each resource group hosting AVD private endpoints) and re-run.' `
            -LearnMore $m.LearnMore
    } else {
        $hasPnaProperty = $script:allHostPools | Where-Object { $null -ne $_.PSObject.Properties['PublicNetworkAccess'] } | Select-Object -First 1
        if (-not $hasPnaProperty) {
            Add-CheckResult -Category Security -CheckName $m.Name -Status Info -Score 100 `
                -Finding 'The installed Az.DesktopVirtualization module does not expose the PublicNetworkAccess property on host pools. Update to Az.DesktopVirtualization 4.0 or later to enable this check.' `
                -Remediation 'Run: Update-Module Az.DesktopVirtualization -Force, then re-run AVD-Assess.' `
                -LearnMore $m.LearnMore
        } else {
            $exposed = [System.Collections.Generic.List[string]]::new()
            $covered = 0
            $scored  = 0

            foreach ($hp in $script:allHostPools) {
                $pna = $hp.PublicNetworkAccess
                if (-not $pna) { continue }   # property absent on this object
                $scored++
                if ($pna -eq 'Disabled') { $covered++; continue }

                $matchingPe = @($script:privateEndpoints | Where-Object {
                    $found = $false
                    foreach ($conn in @($_.PrivateLinkServiceConnections)) {
                        if ($conn.PrivateLinkServiceId -and $conn.PrivateLinkServiceId.StartsWith($hp.Id, [System.StringComparison]::OrdinalIgnoreCase)) {
                            $found = $true
                            break
                        }
                    }
                    $found
                })

                if ($matchingPe.Count -gt 0) {
                    $covered++
                } else {
                    $exposed.Add(('{0} (PublicNetworkAccess: {1})' -f $hp.Name, $pna))
                }
            }

            if ($scored -eq 0) {
                Add-CheckResult -Category Security -CheckName $m.Name -Status Info -Score 100 `
                    -Finding 'None of the assessed host pools expose a PublicNetworkAccess value. Update Az.DesktopVirtualization or check that the host pools were created with a Private Link-capable API version.' `
                    -Remediation $m.Remediation -LearnMore $m.LearnMore
            } elseif ($exposed.Count -eq 0) {
                Add-CheckResult -Category Security -CheckName $m.Name -Status Pass -Score 100 `
                    -Finding ("All {0} host pool(s) are either Private Link fronted or have public network access disabled." -f $scored) `
                    -Remediation '' -LearnMore $m.LearnMore
            } else {
                $pct = [int][math]::Round(($covered / $scored) * 100)
                $shown = ($exposed | Select-Object -First 5) -join '; '
                $more  = if ($exposed.Count -gt 5) { (" (+{0} more)" -f ($exposed.Count - 5)) } else { '' }
                $status = if ($pct -lt 50) { 'Fail' } else { 'Warning' }
                Add-CheckResult -Category Security -CheckName $m.Name -Status $status -Score $pct `
                    -Finding ("{0} of {1} host pool(s) are exposed to public network access without a private endpoint ({2}% covered). Exposed: {3}{4}." -f $exposed.Count, $scored, $pct, $shown, $more) `
                    -Remediation $m.Remediation -LearnMore $m.LearnMore
            }
        }
    }
}

# ==============================================================================
# CHECKS: OPERATIONAL EXCELLENCE
# ==============================================================================

function Invoke-OperationsChecks {
    Write-Section 'Operational Excellence'

    # Check 13: Diagnostic settings
    $m = Get-Check 'DiagnosticSettings'
    if ($script:DiagFetchFailed) {
        Add-CheckResult -Category Operations -CheckName $m.Name -Status Info -Score 100 `
            -Finding 'Unable to read diagnostic settings - permissions to Microsoft.Insights may be missing.' `
            -Remediation 'Grant Monitoring Reader on the host pool resource group(s) and re-run.' `
            -LearnMore $m.LearnMore
    } else {
        $noDiag = @($script:allHostPools | Where-Object {
            $ds = $script:diagnosticSettings[$_.Id]
            (-not $ds) -or ($ds.Count -eq 0) -or -not ($ds | Where-Object { $_.WorkspaceId })
        })
        if ($noDiag.Count -eq 0) {
            Add-CheckResult -Category Operations -CheckName $m.Name -Status Pass -Score 100 `
                -Finding ("All {0} host pool(s) have diagnostic settings sending logs to Log Analytics." -f $script:allHostPools.Count) `
                -Remediation '' -LearnMore $m.LearnMore
        } else {
            $ok = $script:allHostPools.Count - $noDiag.Count
            $pct = [int][math]::Round(($ok / $script:allHostPools.Count) * 100)
            $names = ($noDiag | ForEach-Object { $_.Name }) -join ', '
            Add-CheckResult -Category Operations -CheckName $m.Name -Status Fail -Score $pct `
                -Finding ("{0} of {1} host pool(s) missing diagnostic settings: {2}." -f $noDiag.Count, $script:allHostPools.Count, $names) `
                -Remediation $m.Remediation -LearnMore $m.LearnMore
        }
    }

    # Check 14: Resource tagging
    $m = Get-Check 'ResourceTagging'
    if ($script:TagFetchFailed) {
        Add-CheckResult -Category Operations -CheckName $m.Name -Status Info -Score 100 `
            -Finding 'Unable to read resource tags - permissions may be missing.' `
            -Remediation 'Grant Reader on the subscription or host pool resource groups and re-run.' `
            -LearnMore $m.LearnMore
    } else {
        $missingTags = @($script:allHostPools | Where-Object {
            $tags = $script:hostPoolTags[$_.Id]
            $hasEnv   = $tags -and ($tags.Keys | Where-Object { $_ -ieq 'Environment' })
            $hasOwner = $tags -and ($tags.Keys | Where-Object { $_ -ieq 'Owner' })
            -not ($hasEnv -and $hasOwner)
        })
        if ($missingTags.Count -eq 0) {
            Add-CheckResult -Category Operations -CheckName $m.Name -Status Pass -Score 100 `
                -Finding ("All {0} host pool(s) have Environment and Owner tags." -f $script:allHostPools.Count) `
                -Remediation '' -LearnMore $m.LearnMore
        } else {
            $ok = $script:allHostPools.Count - $missingTags.Count
            $pct = [int][math]::Round(($ok / $script:allHostPools.Count) * 100)
            $names = ($missingTags | ForEach-Object { $_.Name }) -join ', '
            Add-CheckResult -Category Operations -CheckName $m.Name -Status Warning -Score $pct `
                -Finding ("{0} of {1} host pool(s) missing Environment or Owner tag: {2}." -f $missingTags.Count, $script:allHostPools.Count, $names) `
                -Remediation $m.Remediation -LearnMore $m.LearnMore
        }
    }

    # Check 15: Agent update state
    $m = Get-Check 'AgentUpdateState'
    if ($script:allSessionHosts.Count -eq 0) {
        Add-CheckResult -Category Operations -CheckName $m.Name -Status Info -Score 100 `
            -Finding 'No session hosts found.' `
            -Remediation 'No action required.' -LearnMore $m.LearnMore
    } else {
        $badUpdate = @($script:allSessionHosts | Where-Object { $_.UpdateState -in @('Failed','Stalled') })
        if ($badUpdate.Count -eq 0) {
            Add-CheckResult -Category Operations -CheckName $m.Name -Status Pass -Score 100 `
                -Finding 'All session hosts have a healthy agent update state.' `
                -Remediation '' -LearnMore $m.LearnMore
        } else {
            $ok = $script:allSessionHosts.Count - $badUpdate.Count
            $pct = [int][math]::Round(($ok / $script:allSessionHosts.Count) * 100)
            $names = ($badUpdate | ForEach-Object { ($_.Name -split '/')[-1] + " ($($_.UpdateState))" }) -join ', '
            Add-CheckResult -Category Operations -CheckName $m.Name -Status Fail -Score $pct `
                -Finding ("{0} session host(s) have a Failed or Stalled agent update: {1}." -f $badUpdate.Count, $names) `
                -Remediation $m.Remediation -LearnMore $m.LearnMore
        }
    }

    # Check O5: Service Health alerts
    # Walks activity log alerts and matches the ones that:
    #   1) are enabled,
    #   2) carry a category leaf condition of ServiceHealth, and
    #   3) either have no service filter at all (covers all services, including
    #      AVD), or have a filter that explicitly names Azure Virtual Desktop /
    #      Windows Virtual Desktop, or a resourceProvider filter of
    #      Microsoft.DesktopVirtualization.
    # Leaf conditions can be wrapped in AnyOf (e.g. incidentType in [Incident,
    # Maintenance]) - the flattening below hoists those leaves up one level so
    # they're inspected alongside top-level leaves.
    $m = Get-Check 'ServiceHealthAlerts'
    if ($script:ActivityAlertFetchFailed) {
        Add-CheckResult -Category Operations -CheckName $m.Name -Status Info -Score 100 `
            -Finding 'Unable to enumerate activity log alerts - the current identity lacks Microsoft.Insights/activityLogAlerts/read on the subscription.' `
            -Remediation 'Grant Monitoring Reader (or Reader on Microsoft.Insights) on the subscription and re-run.' `
            -LearnMore $m.LearnMore
    } else {
        $avdServiceNames = @('Azure Virtual Desktop', 'Windows Virtual Desktop')
        $avdProvider     = 'Microsoft.DesktopVirtualization'
        $matchingAlerts  = [System.Collections.Generic.List[string]]::new()

        foreach ($alert in $script:activityLogAlerts) {
            # Disabled alerts don't fire even if their conditions match.
            if ($null -ne $alert.PSObject.Properties['Enabled'] -and $alert.Enabled -eq $false) { continue }
            if (-not $alert.Condition -or -not $alert.Condition.AllOf) { continue }

            $leaves = [System.Collections.Generic.List[object]]::new()
            foreach ($entry in $alert.Condition.AllOf) {
                if ($entry.AnyOf) {
                    foreach ($nested in $entry.AnyOf) { $leaves.Add($nested) }
                } else {
                    $leaves.Add($entry)
                }
            }

            $isServiceHealth = $false
            foreach ($leaf in $leaves) {
                if (-not $leaf.Field -or ($leaf.Field -ine 'category')) { continue }
                if ($leaf.Equals -and ($leaf.Equals -ieq 'ServiceHealth')) { $isServiceHealth = $true; break }
                if ($leaf.ContainsAny -and (@($leaf.ContainsAny) | Where-Object { $_ -ieq 'ServiceHealth' })) {
                    $isServiceHealth = $true; break
                }
            }
            if (-not $isServiceHealth) { continue }

            $serviceFilters = @($leaves | Where-Object {
                $_.Field -and (
                    ($_.Field -ieq 'resourceProvider') -or
                    ($_.Field -match '(?i)impactedservices.*servicename')
                )
            })

            $coversAvd = $false
            if ($serviceFilters.Count -eq 0) {
                # No service / provider filter at all -> matches every service.
                $coversAvd = $true
            } else {
                foreach ($filter in $serviceFilters) {
                    $targets = if ($filter.Field -ieq 'resourceProvider') { @($avdProvider) } else { $avdServiceNames }
                    if ($filter.Equals -and ($targets | Where-Object { $_ -ieq $filter.Equals })) {
                        $coversAvd = $true; break
                    }
                    if ($filter.ContainsAny) {
                        $hit = @($filter.ContainsAny | Where-Object {
                            $val = $_
                            $targets | Where-Object { $_ -ieq $val }
                        })
                        if ($hit.Count -gt 0) { $coversAvd = $true; break }
                    }
                }
            }

            if ($coversAvd) { $matchingAlerts.Add($alert.Name) }
        }

        if ($matchingAlerts.Count -gt 0) {
            $shown = ($matchingAlerts | Select-Object -First 3) -join ', '
            $more  = if ($matchingAlerts.Count -gt 3) { (" (+{0} more)" -f ($matchingAlerts.Count - 3)) } else { '' }
            Add-CheckResult -Category Operations -CheckName $m.Name -Status Pass -Score 100 `
                -Finding ("{0} Service Health alert rule(s) cover Azure Virtual Desktop on this subscription: {1}{2}." -f $matchingAlerts.Count, $shown, $more) `
                -Remediation '' -LearnMore $m.LearnMore
        } else {
            $totalAlerts = $script:activityLogAlerts.Count
            $context = if ($totalAlerts -eq 0) {
                'No activity log alerts exist on this subscription.'
            } else {
                ("{0} activity log alert rule(s) exist on this subscription, but none cover Azure Virtual Desktop Service Health events." -f $totalAlerts)
            }
            Add-CheckResult -Category Operations -CheckName $m.Name -Status Warning -Score 40 `
                -Finding ("No Service Health alerts cover Azure Virtual Desktop. {0} There is no proactive notification channel for planned maintenance, service issues, or health advisories from Microsoft." -f $context) `
                -Remediation $m.Remediation -LearnMore $m.LearnMore
        }
    }

    # Check 16: Load balancing algorithm (always Pass / informational)
    $m = Get-Check 'LoadBalancingAlgorithm'
    if ($script:pooledHostPools.Count -eq 0) {
        Add-CheckResult -Category Operations -CheckName $m.Name -Status Info -Score 100 `
            -Finding 'No pooled host pools found. Load balancing algorithm applies to pooled host pools only.' `
            -Remediation 'No action required.' -LearnMore $m.LearnMore
    } else {
        $bf = @($script:pooledHostPools | Where-Object { $_.LoadBalancerType -eq 'BreadthFirst' }).Count
        $df = @($script:pooledHostPools | Where-Object { $_.LoadBalancerType -eq 'DepthFirst' }).Count
        Add-CheckResult -Category Operations -CheckName $m.Name -Status Pass -Score 100 `
            -Finding ("Load balancing review: {0} pool(s) use BreadthFirst (performance-optimised - spreads users across more VMs), {1} pool(s) use DepthFirst (cost-optimised - fills VMs before starting new ones)." -f $bf, $df) `
            -Remediation $m.Remediation -LearnMore $m.LearnMore
    }
}

# ==============================================================================
# CHECKS: PERFORMANCE EFFICIENCY
# ==============================================================================

function Invoke-PerformanceChecks {
    Write-Section 'Performance Efficiency'

    # Map session host VM resource IDs to their host pool type so PE2 can
    # distinguish multi-session (Pooled) vs personal pool members - WAF
    # guidance is stricter on disk SKU for the former.
    $vmHostPoolType = @{}
    foreach ($sh in $script:allSessionHosts) {
        if ($sh.ResourceId) { $vmHostPoolType[$sh.ResourceId] = $sh._HostPoolType }
    }

    # Check PE1: Accelerated Networking
    # Pass = 100% of session host NICs have it enabled.
    # Warning = proportional shortfall (score == % enabled).
    # Info = no NIC data available (permission denied or no AVD VMs).
    $m = Get-Check 'AcceleratedNetworking'

    if ($script:NicFetchFailed -or $script:vmNics.Count -eq 0) {
        Add-CheckResult -Category Performance -CheckName $m.Name -Status Info -Score 100 `
            -Finding 'No NIC data available - either the assessed scope has no session host VMs, or the current identity lacks Microsoft.Network/networkInterfaces/read on the session host resource groups.' `
            -Remediation $m.Remediation -LearnMore $m.LearnMore
    } else {
        $totalNics    = $script:vmNics.Count
        $enabledNics  = 0
        $disabledHosts = [System.Collections.Generic.List[string]]::new()

        foreach ($vm in $script:allVMs) {
            if (-not $script:vmNics.ContainsKey($vm.Id)) { continue }
            $nic = $script:vmNics[$vm.Id]
            if ($nic.EnableAcceleratedNetworking) {
                $enabledNics++
            } else {
                $disabledHosts.Add($vm.Name)
            }
        }

        if ($disabledHosts.Count -eq 0) {
            Add-CheckResult -Category Performance -CheckName $m.Name -Status Pass -Score 100 `
                -Finding ("All {0} session host NIC(s) have Accelerated Networking enabled." -f $totalNics) `
                -Remediation '' -LearnMore $m.LearnMore
        } else {
            $pct = [int][math]::Round(($enabledNics / $totalNics) * 100)
            # Show up to 5 affected hosts inline; summarise the rest.
            $shown = ($disabledHosts | Select-Object -First 5) -join ', '
            $more  = if ($disabledHosts.Count -gt 5) { (" (+{0} more)" -f ($disabledHosts.Count - 5)) } else { '' }
            $status = if ($pct -eq 0) { 'Fail' } else { 'Warning' }
            Add-CheckResult -Category Performance -CheckName $m.Name -Status $status -Score $pct `
                -Finding ("{0} of {1} session host NIC(s) have Accelerated Networking enabled ({2}%). Disabled on: {3}{4}." -f $enabledNics, $totalNics, $pct, $shown, $more) `
                -Remediation $m.Remediation -LearnMore $m.LearnMore
        }
    }

    # Check PE2: OS Disk Performance Tier (Premium SSD for multi-session)
    # Premium / PremiumV2 / Ultra / Premium_ZRS all count as "premium" here.
    # Scoring is based on multi-session (Pooled) hosts only - personal pools
    # get softer WAF guidance and are reported separately in the finding text.
    $m = Get-Check 'PremiumOsDisk'
    $premiumSkus = @('Premium_LRS','PremiumV2_LRS','UltraSSD_LRS','Premium_ZRS')

    if ($script:DiskFetchFailed -or $script:vmOsDisks.Count -eq 0) {
        Add-CheckResult -Category Performance -CheckName $m.Name -Status Info -Score 100 `
            -Finding 'No OS disk data available - either the assessed scope has no session host VMs, or the current identity lacks Microsoft.Compute/disks/read on the session host resource groups.' `
            -Remediation $m.Remediation -LearnMore $m.LearnMore
    } else {
        $msSubPremium = [System.Collections.Generic.List[string]]::new()
        $msTotal     = 0
        $personalSubPremium = [System.Collections.Generic.List[string]]::new()

        foreach ($vm in $script:allVMs) {
            if (-not $script:vmOsDisks.ContainsKey($vm.Id)) { continue }
            $disk = $script:vmOsDisks[$vm.Id]
            $sku  = $disk.Sku.Name
            $isPremium = $premiumSkus -contains $sku
            $type = $vmHostPoolType[$vm.Id]
            if ($type -eq 'Personal') {
                if (-not $isPremium) { $personalSubPremium.Add(('{0} ({1})' -f $vm.Name, $sku)) }
            } else {
                $msTotal++
                if (-not $isPremium) { $msSubPremium.Add(('{0} ({1})' -f $vm.Name, $sku)) }
            }
        }

        if ($msTotal -eq 0 -and $personalSubPremium.Count -eq 0) {
            Add-CheckResult -Category Performance -CheckName $m.Name -Status Pass -Score 100 `
                -Finding 'All session host OS disks are Premium SSD or better.' `
                -Remediation '' -LearnMore $m.LearnMore
        } elseif ($msTotal -eq 0) {
            # Only personal hosts present, and some are sub-premium - Info-level
            # because WAF guidance is softer for personal desktops.
            Add-CheckResult -Category Performance -CheckName $m.Name -Status Info -Score 100 `
                -Finding ("{0} personal session host(s) use sub-premium OS disks. WAF allows Standard SSD for personal desktops but Premium SSD still wins on logon and app launch performance." -f $personalSubPremium.Count) `
                -Remediation $m.Remediation -LearnMore $m.LearnMore
        } elseif ($msSubPremium.Count -eq 0) {
            $tail = if ($personalSubPremium.Count -gt 0) {
                (" {0} personal host(s) on sub-premium disks (Info - softer WAF guidance applies)." -f $personalSubPremium.Count)
            } else { '' }
            Add-CheckResult -Category Performance -CheckName $m.Name -Status Pass -Score 100 `
                -Finding ("All {0} multi-session host OS disks are Premium SSD or better.{1}" -f $msTotal, $tail) `
                -Remediation '' -LearnMore $m.LearnMore
        } else {
            $okMs   = $msTotal - $msSubPremium.Count
            $pct    = [int][math]::Round(($okMs / $msTotal) * 100)
            $shown  = ($msSubPremium | Select-Object -First 5) -join ', '
            $more   = if ($msSubPremium.Count -gt 5) { (" (+{0} more)" -f ($msSubPremium.Count - 5)) } else { '' }
            $status = if ($pct -lt 50) { 'Fail' } else { 'Warning' }
            $tail   = if ($personalSubPremium.Count -gt 0) {
                (" {0} additional personal host(s) on sub-premium disks (Info - softer WAF guidance)." -f $personalSubPremium.Count)
            } else { '' }
            Add-CheckResult -Category Performance -CheckName $m.Name -Status $status -Score $pct `
                -Finding ("{0} of {1} multi-session host OS disk(s) are Premium SSD or better ({2}%). Sub-premium: {3}{4}.{5}" -f $okMs, $msTotal, $pct, $shown, $more, $tail) `
                -Remediation $m.Remediation -LearnMore $m.LearnMore
        }
    }

    # Check PE3: VM Generation (Gen2)
    # Reads HyperVGeneration on the OS disk (V1 / V2). Pass if all Gen2,
    # proportional Warning/Fail if any Gen1.
    $m = Get-Check 'Gen2VirtualMachines'

    if ($script:DiskFetchFailed -or $script:vmOsDisks.Count -eq 0) {
        Add-CheckResult -Category Performance -CheckName $m.Name -Status Info -Score 100 `
            -Finding 'No OS disk data available to determine VM generation. Requires Microsoft.Compute/disks/read on the session host resource groups.' `
            -Remediation $m.Remediation -LearnMore $m.LearnMore
    } else {
        $gen1Hosts = [System.Collections.Generic.List[string]]::new()
        $total = 0
        foreach ($vm in $script:allVMs) {
            if (-not $script:vmOsDisks.ContainsKey($vm.Id)) { continue }
            $disk = $script:vmOsDisks[$vm.Id]
            $total++
            # HyperVGeneration is 'V1' or 'V2'. Missing == treat as Gen1 (older
            # disks predated the property and historically were always Gen1).
            $gen = if ($disk.HyperVGeneration) { $disk.HyperVGeneration } else { 'V1' }
            if ($gen -ne 'V2') { $gen1Hosts.Add($vm.Name) }
        }

        if ($total -eq 0) {
            Add-CheckResult -Category Performance -CheckName $m.Name -Status Info -Score 100 `
                -Finding 'No session host disks available to evaluate VM generation.' `
                -Remediation $m.Remediation -LearnMore $m.LearnMore
        } elseif ($gen1Hosts.Count -eq 0) {
            Add-CheckResult -Category Performance -CheckName $m.Name -Status Pass -Score 100 `
                -Finding ("All {0} session host(s) are Gen2 VMs." -f $total) `
                -Remediation '' -LearnMore $m.LearnMore
        } else {
            $ok = $total - $gen1Hosts.Count
            $pct = [int][math]::Round(($ok / $total) * 100)
            $shown = ($gen1Hosts | Select-Object -First 5) -join ', '
            $more  = if ($gen1Hosts.Count -gt 5) { (" (+{0} more)" -f ($gen1Hosts.Count - 5)) } else { '' }
            $status = if ($pct -lt 50) { 'Fail' } else { 'Warning' }
            Add-CheckResult -Category Performance -CheckName $m.Name -Status $status -Score $pct `
                -Finding ("{0} of {1} session host(s) are Gen2 VMs ({2}%). Gen1 hosts: {3}{4}." -f $ok, $total, $pct, $shown, $more) `
                -Remediation $m.Remediation -LearnMore $m.LearnMore
        }
    }

    # Check PE4: FSLogix Region Colocation
    # Cross-region FSLogix profile traffic adds 40-80ms per OpenFile, which
    # silently degrades every application launch. The discovery method is
    # recorded in the finding text so admins can judge how much to trust the
    # auto-detection - explicit override > tag > name pattern.
    $m = Get-Check 'FSLogixRegionColocation'
    $fslogixLinks = [System.Collections.Generic.List[object]]::new()
    foreach ($hp in $script:allHostPools) {
        $d = $script:fslogixDiscovery[$hp.Id]
        if ($d -and $d.StorageAccount) {
            $fslogixLinks.Add([PSCustomObject]@{
                HostPool       = $hp
                StorageAccount = $d.StorageAccount
                Method         = $d.Method
            })
        }
    }

    if ($script:StorageFetchFailed) {
        Add-CheckResult -Category Performance -CheckName $m.Name -Status Info -Score 100 `
            -Finding 'Cannot evaluate FSLogix region colocation: storage account read access was denied on every resource group containing a host pool.' `
            -Remediation $m.Remediation -LearnMore $m.LearnMore
    } elseif ($fslogixLinks.Count -eq 0) {
        Add-CheckResult -Category Performance -CheckName $m.Name -Status Info -Score 100 `
            -Finding "FSLogix storage could not be auto-discovered for any host pool. Re-run with -FSLogixStorageAccount <name> to override, tag a host pool with 'FSLogixStorageAccount' = <storage account name>, or ensure the FSLogix storage account name matches the -FSLogixNamePattern (default '*fslogix*')." `
            -Remediation $m.Remediation -LearnMore $m.LearnMore
    } else {
        $crossRegion = [System.Collections.Generic.List[string]]::new()
        foreach ($link in $fslogixLinks) {
            if ($link.HostPool.Location -ne $link.StorageAccount.Location) {
                $crossRegion.Add(('{0} ({1} pool / {2} storage)' -f $link.HostPool.Name, $link.HostPool.Location, $link.StorageAccount.Location))
            }
        }
        $methodSummary = ($fslogixLinks | Group-Object Method | ForEach-Object { ('{0}: {1}' -f $_.Name, $_.Count) }) -join ', '
        if ($crossRegion.Count -eq 0) {
            Add-CheckResult -Category Performance -CheckName $m.Name -Status Pass -Score 100 `
                -Finding ("All {0} discovered FSLogix storage account(s) are colocated with their host pool. Discovery method: {1}." -f $fslogixLinks.Count, $methodSummary) `
                -Remediation '' -LearnMore $m.LearnMore
        } else {
            $ok  = $fslogixLinks.Count - $crossRegion.Count
            $pct = [int][math]::Round(($ok / $fslogixLinks.Count) * 100)
            $shown = ($crossRegion | Select-Object -First 5) -join '; '
            $more  = if ($crossRegion.Count -gt 5) { (" (+{0} more)" -f ($crossRegion.Count - 5)) } else { '' }
            $status = if ($pct -lt 50) { 'Fail' } else { 'Warning' }
            Add-CheckResult -Category Performance -CheckName $m.Name -Status $status -Score $pct `
                -Finding ("{0} of {1} host pool(s) have FSLogix storage in a different region ({2}% colocated). Cross-region: {3}{4}. Discovery method: {5}." -f $crossRegion.Count, $fslogixLinks.Count, $pct, $shown, $more, $methodSummary) `
                -Remediation $m.Remediation -LearnMore $m.LearnMore
        }
    }
}

# ==============================================================================
# SCORING
# ==============================================================================

function Get-CategoryScore {
    param([string]$Category)
    $items = @($script:Checks | Where-Object { $_.Category -eq $Category -and $_.Status -ne 'Info' })
    if ($items.Count -eq 0) { return 100 }
    $avg = ($items | Measure-Object -Property Score -Average).Average
    return [int][math]::Round($avg)
}

function Get-OverallScore {
    $cats = @('Cost','Reliability','Security','Operations','Performance')
    $scores = $cats | ForEach-Object { Get-CategoryScore $_ }
    return [int][math]::Round(($scores | Measure-Object -Average).Average)
}

# ==============================================================================
# HTML REPORT
# ==============================================================================

function New-CategoryCardHtml {
    param([string]$Category, [string]$DisplayName)
    $score  = Get-CategoryScore -Category $Category
    $donut  = New-DonutSvg -Score $score -Size 96
    $checks = @($script:Checks | Where-Object { $_.Category -eq $Category })

    $rows = [System.Text.StringBuilder]::new()
    foreach ($c in $checks) {
        $cls    = Get-StatusClass -Status $c.Status
        $label  = Get-StatusSymbol -Status $c.Status
        $name   = ConvertTo-HtmlSafe $c.CheckName
        $find   = ConvertTo-HtmlSafe $c.Finding
        $rem    = ConvertTo-HtmlSafe $c.Remediation
        $learn  = ''
        if ($c.LearnMore) {
            $urlSafe = ConvertTo-HtmlSafe $c.LearnMore
            $learn   = "<a class=""learn"" href=""$urlSafe"" target=""_blank"" rel=""noopener"">Microsoft Learn &rarr;</a>"
        }
        $remBlock = ''
        if ($c.Remediation) {
            $remBlock = @"
      <div class="remediation">
        <div class="rem-label">Remediation</div>
        <div>$rem</div>
        $learn
      </div>
"@
        } elseif ($learn) {
            $remBlock = "<div class=""remediation-link"">$learn</div>"
        }
        [void]$rows.AppendLine(@"
  <div class="check-row" onclick="this.classList.toggle('expanded')">
    <div class="check-head">
      <span class="check-name">$name</span>
      <span class="status $cls">$label</span>
    </div>
    <div class="check-detail">
      <div class="finding">$find</div>
$remBlock
    </div>
  </div>
"@)
    }

    return @"
<section class="category-card">
  <div class="category-head">
    $donut
    <div class="category-meta">
      <div class="sub">$DisplayName</div>
      <div class="cat-score">$score<span class="cat-score-suffix">/100</span></div>
    </div>
  </div>
  <div class="check-list">
$($rows.ToString())
  </div>
</section>
"@
}

function New-HtmlReport {
    $overall = Get-OverallScore
    $overallDonut = New-DonutSvg -Score $overall -Size 140
    $generated = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz')

    $subName = ConvertTo-HtmlSafe $script:Context.SubscriptionName
    $subId   = ConvertTo-HtmlSafe $script:Context.SubscriptionId
    $tenant  = ConvertTo-HtmlSafe $script:Context.TenantId

    $cardCost   = New-CategoryCardHtml -Category 'Cost'        -DisplayName 'Cost Optimisation'
    $cardRel    = New-CategoryCardHtml -Category 'Reliability' -DisplayName 'Reliability & Resilience'
    $cardSec    = New-CategoryCardHtml -Category 'Security'    -DisplayName 'Security Posture'
    $cardOps    = New-CategoryCardHtml -Category 'Operations'  -DisplayName 'Operational Excellence'
    $cardPerf   = New-CategoryCardHtml -Category 'Performance' -DisplayName 'Performance Efficiency'

    $css = @'
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  background: #0a1f2e;
  color: #ffffff;
  line-height: 1.5;
  min-height: 100vh;
  -webkit-font-smoothing: antialiased;
}
.container { max-width: 1200px; margin: 0 auto; padding: 32px 24px 48px; }
header.hero {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 24px;
  background: #0D2535;
  border: 1px solid #1a3547;
  border-radius: 16px;
  padding: 32px;
  margin-bottom: 20px;
}
.brand {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.brand-name {
  font-size: 36px;
  font-weight: 800;
  letter-spacing: -0.02em;
  color: #ffffff;
}
.brand-name .dot { color: #B3FF00; }
.brand-sub {
  font-size: 13px;
  color: #94a3b8;
  letter-spacing: 0.02em;
}
.overall {
  display: flex;
  align-items: center;
  gap: 20px;
}
.overall .label {
  font-size: 11px;
  color: #94a3b8;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  margin-bottom: 4px;
}
.overall .big {
  font-size: 54px;
  font-weight: 800;
  color: #ffffff;
  line-height: 1;
  letter-spacing: -0.02em;
}
.overall .suffix {
  font-size: 20px;
  font-weight: 600;
  color: #64748b;
  margin-left: 4px;
}
.meta-bar {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
  gap: 1px;
  background: #1a3547;
  border: 1px solid #1a3547;
  border-radius: 12px;
  overflow: hidden;
  margin-bottom: 28px;
}
.meta-bar .cell { background: #0D2535; padding: 14px 18px; }
.meta-bar .meta-label {
  font-size: 10px;
  color: #94a3b8;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  margin-bottom: 5px;
  font-weight: 600;
}
.meta-bar .meta-value {
  font-size: 14px;
  color: #ffffff;
  font-weight: 500;
  word-break: break-all;
}
/* 3+2 grid for the 5 WAF categories. Top row: Cost / Reliability / Security
   each spans 2 of 6 columns. Bottom row: Operations / Performance each spans
   3 of 6 columns so they share the full width evenly. Stacks 2-up below
   1100px and 1-up below 760px. */
.categories {
  display: grid;
  grid-template-columns: repeat(6, 1fr);
  gap: 20px;
}
.categories > .category-card { grid-column: span 2; }
.categories > .category-card:nth-child(4),
.categories > .category-card:nth-child(5) { grid-column: span 3; }
@media (max-width: 1100px) {
  .categories { grid-template-columns: repeat(2, 1fr); }
  .categories > .category-card,
  .categories > .category-card:nth-child(4),
  .categories > .category-card:nth-child(5) { grid-column: span 1; }
}
.category-card {
  background: #0D2535;
  border: 1px solid #1a3547;
  border-radius: 16px;
  padding: 28px;
}
.category-head {
  display: flex;
  align-items: center;
  gap: 20px;
  margin-bottom: 20px;
  padding-bottom: 20px;
  border-bottom: 1px solid #1a3547;
}
.category-meta .sub {
  font-size: 11px;
  color: #94a3b8;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  font-weight: 600;
  margin-bottom: 4px;
}
.category-meta .cat-score {
  font-size: 34px;
  font-weight: 800;
  color: #ffffff;
  line-height: 1;
  letter-spacing: -0.02em;
}
.category-meta .cat-score-suffix {
  font-size: 14px;
  color: #64748b;
  font-weight: 600;
  margin-left: 3px;
}
.check-list { display: flex; flex-direction: column; gap: 4px; }
.check-row {
  cursor: pointer;
  border-radius: 8px;
  transition: background 140ms ease;
  user-select: none;
}
.check-row:hover { background: rgba(255,255,255,0.03); }
.check-row.expanded { background: rgba(255,255,255,0.04); }
.check-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  padding: 12px 14px;
}
.check-name { font-size: 14px; color: #ffffff; font-weight: 500; }
.status {
  display: inline-flex;
  align-items: center;
  padding: 3px 10px;
  border-radius: 12px;
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  white-space: nowrap;
  flex-shrink: 0;
}
.status.pass { color: #22c55e; background: rgba(34,197,94,0.12);  border: 1px solid rgba(34,197,94,0.35); }
.status.warn { color: #f59e0b; background: rgba(245,158,11,0.12); border: 1px solid rgba(245,158,11,0.35); }
.status.fail { color: #ef4444; background: rgba(239,68,68,0.12);  border: 1px solid rgba(239,68,68,0.35); }
.status.info { color: #33CCCC; background: rgba(51,204,204,0.12); border: 1px solid rgba(51,204,204,0.35); }
.check-detail {
  display: none;
  padding: 4px 14px 14px 14px;
  font-size: 13px;
  color: #cbd5e1;
}
.check-row.expanded .check-detail { display: block; }
.check-detail .finding { margin-bottom: 12px; line-height: 1.6; }
.check-detail .remediation {
  background: rgba(51,204,204,0.06);
  border-left: 3px solid #33CCCC;
  padding: 12px 14px;
  border-radius: 4px;
  color: #e2e8f0;
  line-height: 1.6;
}
.check-detail .rem-label {
  font-size: 11px;
  color: #33CCCC;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  margin-bottom: 6px;
}
.learn {
  display: inline-block;
  margin-top: 10px;
  color: #33CCCC;
  text-decoration: none;
  font-weight: 500;
  font-size: 13px;
  border-bottom: 1px dashed rgba(51,204,204,0.5);
  padding-bottom: 1px;
}
.learn:hover { color: #B3FF00; border-bottom-color: #B3FF00; }
.remediation-link { margin-top: 8px; }
.donut { flex-shrink: 0; }
footer {
  margin-top: 32px;
  padding-top: 24px;
  border-top: 1px solid #1a3547;
  color: #64748b;
  font-size: 13px;
  text-align: center;
}
footer a { color: #33CCCC; text-decoration: none; }
footer a:hover { color: #B3FF00; }
@media (max-width: 760px) {
  header.hero { flex-direction: column; align-items: flex-start; }
  .overall { align-self: flex-end; }
  .categories { grid-template-columns: 1fr; }
  .categories > .category-card,
  .categories > .category-card:nth-child(4),
  .categories > .category-card:nth-child(5) { grid-column: span 1; }
}
'@

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AVD-Assess Report &mdash; $subName</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>$css</style>
</head>
<body>
<div class="container">
  <header class="hero">
    <div class="brand">
      <div class="brand-name">AVD<span class="dot">-</span>Assess</div>
      <div class="brand-sub">Azure Virtual Desktop Health Report</div>
    </div>
    <div class="overall">
      $overallDonut
      <div>
        <div class="label">Overall Score</div>
        <div class="big">$overall<span class="suffix">/100</span></div>
      </div>
    </div>
  </header>

  <div class="meta-bar">
    <div class="cell"><div class="meta-label">Subscription</div><div class="meta-value">$subName</div></div>
    <div class="cell"><div class="meta-label">Subscription ID</div><div class="meta-value">$subId</div></div>
    <div class="cell"><div class="meta-label">Tenant</div><div class="meta-value">$tenant</div></div>
    <div class="cell"><div class="meta-label">Host Pools</div><div class="meta-value">$($script:HostPoolCount)</div></div>
    <div class="cell"><div class="meta-label">Session Hosts</div><div class="meta-value">$($script:SessionHostCount)</div></div>
    <div class="cell"><div class="meta-label">Generated</div><div class="meta-value">$generated</div></div>
  </div>

  <div class="categories">
    $cardCost
    $cardRel
    $cardSec
    $cardOps
    $cardPerf
  </div>

  <footer>
    AVD-Assess v$script:ToolVersion &middot;
    <a href="$script:WebsiteUrl" target="_blank" rel="noopener">modern-euc.com</a> &middot;
    <a href="$script:ProjectUrl" target="_blank" rel="noopener">github.com/waynebellows/AVD-Assess</a>
  </footer>
</div>
</body>
</html>
"@
    return $html
}

# ==============================================================================
# MAIN
# ==============================================================================

function Invoke-Main {
    Write-Banner

    if ($DryRun) {
        Initialize-DryRunData
    } else {
        Assert-RequiredModules
        Connect-ToAzure
        $hasData = Get-AvdEnvironmentData
        if (-not $hasData) {
            Write-Host ''
            Write-Host '  Nothing to report. Exiting.' -ForegroundColor Yellow
            return
        }
        Invoke-CostChecks
        Invoke-ReliabilityChecks
        Invoke-SecurityChecks
        Invoke-OperationsChecks
        Invoke-PerformanceChecks
    }

    # Score summary
    $cost = Get-CategoryScore 'Cost'
    $rel  = Get-CategoryScore 'Reliability'
    $sec  = Get-CategoryScore 'Security'
    $ops  = Get-CategoryScore 'Operations'
    $perf = Get-CategoryScore 'Performance'
    $overall = Get-OverallScore

    Write-Section 'Score Summary'
    Write-Host ("  Cost Optimisation      : {0}/100" -f $cost)    -ForegroundColor White
    Write-Host ("  Reliability            : {0}/100" -f $rel)     -ForegroundColor White
    Write-Host ("  Security Posture       : {0}/100" -f $sec)     -ForegroundColor White
    Write-Host ("  Operational Excellence : {0}/100" -f $ops)     -ForegroundColor White
    Write-Host ("  Performance Efficiency : {0}/100" -f $perf)    -ForegroundColor White
    Write-Host ''
    Write-Host ("  Overall Score          : {0}/100" -f $overall) -ForegroundColor Cyan

    # Render HTML
    $html = New-HtmlReport

    if (-not $OutputPath) {
        $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
        $OutputPath = Join-Path -Path (Get-Location).Path -ChildPath "AVD-Assess-Report-$stamp.html"
    }
    $outDir = Split-Path -Parent $OutputPath
    if ($outDir -and -not (Test-Path $outDir)) {
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    }
    [System.IO.File]::WriteAllText($OutputPath, $html, [System.Text.UTF8Encoding]::new($false))

    Write-Host ''
    Write-Host ("  Report saved to: {0}" -f $OutputPath) -ForegroundColor Green
    Write-Host ''

    if ($OpenReport) {
        try { Start-Process -FilePath $OutputPath | Out-Null }
        catch { Write-Host "  (Could not open report automatically: $($_.Exception.Message))" -ForegroundColor Yellow }
    }
}

Invoke-Main
