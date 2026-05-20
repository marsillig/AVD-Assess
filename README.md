# AVD-Scout

**AVD-Scout is a Virtex-branded Azure Virtual Desktop assessment tool for consultants and operators.** It connects to an Azure subscription, runs **29 read-only best-practice checks** across the five [Microsoft Well-Architected Framework pillars for Azure Virtual Desktop](https://learn.microsoft.com/azure/well-architected/azure-virtual-desktop/), and generates a shareable HTML report plus optional JSON for trend tracking and automation.

AVD-Scout is Gonzalo Marsilli's renamed fork of the original [WayneBellows/AVD-Assess](https://github.com/WayneBellows/AVD-Assess) project by Wayne Bellows. This fork keeps the original MIT-licensed foundation and adds Cloud Shell fixes, 2026 AVD readiness checks, Virtex styling, updated report branding, and fork-specific usage paths.

![AVD-Scout Report](docs/screenshot.png)

## What this fork adds

- **2026 AVD readiness checks** for dynamic autoscaling, modern RDP transport, client redirection hardening, platform currency, and AVD Classic retirement awareness.
- **Virtex report experience** with a light Virtex-inspired palette and footer branding: `AVD-Scout v2.0.0 · https://virtex.cloud · github.com/marsillig/AVD-Scout`.
- **Azure Cloud Shell compatibility** including reliable relative and `~` output path handling.
- **Readable dated filenames** such as `AVD-Scout-Report-2026-05-19_23-26-07.html`.
- **Fork-aligned docs and URLs** for cloning, Cloud Shell download, and generated report links.

## What it checks

**Cost Optimisation** — scaling plan coverage on pooled host pools; Start VM on Connect across personal and pooled pools; unhealthy hosts still in session rotation; max session limit configuration; dynamic autoscaling readiness for elastic 2026 host pools.

**Reliability & Resilience** — session host health; modern RDP transport readiness including Shortpath, UDP/network auto-detect, and Multipath signals; agent update ring split; session capacity headroom; FSLogix profile redundancy; availability zone distribution.

**Security Posture** — drive redirection; clipboard redirection; 2025+ client redirection hardening across clipboard, drive, printer, and USB redirection; Trusted Launch / Secure Boot; Entra ID join status; Defender for Cloud coverage; AVD Private Link / public network access.

**Operational Excellence** — diagnostic settings to Log Analytics; resource tagging; AVD agent update state; Azure Service Health alerts; load balancing algorithm review; AVD Classic retirement readiness before 30 September 2026.

**Performance Efficiency** — Accelerated Networking; OS disk performance tier; VM generation; Windows 11 24H2 / Windows Server 2025 platform currency; FSLogix region colocation.

Every finding names affected resources where possible, explains the risk, recommends concrete remediation, and links to Microsoft Learn.

## Prerequisites

- **PowerShell 7+** — [install PowerShell](https://learn.microsoft.com/powershell/scripting/install/installing-powershell)
- **Az PowerShell modules** — `Az.Accounts`, `Az.DesktopVirtualization`, `Az.Compute`, `Az.Monitor`, `Az.Resources`, `Az.Network`, `Az.Storage`, `Az.Security`
- **Azure permissions** — `Reader` covers most checks. Some checks benefit from additional read-only permissions:
  - **Defender for Cloud coverage** — `Microsoft.Security/pricings/read`, typically via *Security Reader*
  - **Service Health alerts** — `Microsoft.Insights/activityLogAlerts/read`, typically via *Monitoring Reader*

Checks degrade to `Info` rather than failing the run when optional permissions are missing.

## Quick start

```powershell
# Install required modules once
Install-Module Az.Accounts, Az.DesktopVirtualization, Az.Compute, Az.Monitor, Az.Resources, Az.Network, Az.Storage, Az.Security -Scope CurrentUser

# Clone this fork
git clone https://github.com/marsillig/AVD-Scout.git
cd AVD-Scout

# Run against your current Azure context
./AVD-Scout.ps1 -OpenReport
```

By default, AVD-Scout writes a timestamped report like:

```text
AVD-Scout-Report-yyyy-MM-dd_HH-mm-ss.html
```

## Running from Azure Cloud Shell

AVD-Scout works in [Azure Cloud Shell](https://shell.azure.com) PowerShell mode.

```powershell
# 1. Install modules Cloud Shell might not already have
Install-Module Az.DesktopVirtualization, Az.Security -Scope CurrentUser -Force

# 2. Clone this fork. git clone creates the AVD-Scout directory.
git clone https://github.com/marsillig/AVD-Scout.git
cd AVD-Scout

# 3. Run using the existing Cloud Shell sign-in and write the report into the repo folder.
./AVD-Scout.ps1 -UseExistingConnection -OutputPath ./AVD-Scout-Report.html
```

Then use **Manage files → Download** in Cloud Shell to download `AVD-Scout/AVD-Scout-Report.html`.

## Common usage

```powershell
# Generate HTML only
./AVD-Scout.ps1 -UseExistingConnection

# Generate HTML and JSON
./AVD-Scout.ps1 -UseExistingConnection -OutputFormat Both -OutputPath .\avd-scout.html

# Compare against a previous JSON report
./AVD-Scout.ps1 -UseExistingConnection -OutputFormat Both -CompareTo .\avd-scout.json

# Assess one host pool
./AVD-Scout.ps1 -HostPoolName "hp-prod-pooled-01" -ResourceGroupName "rg-avd-prod"

# Sweep every enabled subscription visible to the signed-in identity
./AVD-Scout.ps1 -AllAccessibleSubscriptions -UseExistingConnection -OutputFormat Both -OpenReport

# Render synthetic data without Azure calls
./AVD-Scout.ps1 -DryRun -OutputPath .\_dryrun.html -OpenReport
```

## Parameters

| Parameter | Description | Example |
|---|---|---|
| `-SubscriptionId` | Azure subscription ID to assess. Uses current Az context if omitted. | `00000000-0000-0000-0000-000000000000` |
| `-TenantId` | Azure tenant ID. Uses current Az context if omitted. | `11111111-1111-1111-1111-111111111111` |
| `-OutputPath` | Report path. Defaults to timestamped HTML. In sweep mode, this is the output directory. | `C:\Reports\avd-scout.html` |
| `-OutputFormat` | `HTML`, `JSON`, or `Both`. | `Both` |
| `-CompareTo` | Previous JSON report for score deltas and new/removed check tracking. | `.\AVD-Scout-Report-2026-04-01_09-00-00.json` |
| `-AllAccessibleSubscriptions` | Sweep every enabled subscription visible to the identity. | switch |
| `-HostPoolName` | Scope to one host pool. Requires `-ResourceGroupName`. | `hp-prod-pooled-01` |
| `-ResourceGroupName` | Scope to one resource group or pair with `-HostPoolName`. | `rg-avd-prod` |
| `-UseExistingConnection` | Reuse current Az login instead of calling `Connect-AzAccount`. | switch |
| `-OpenReport` | Open the HTML report after generation. Avoid in Cloud Shell. | switch |
| `-DryRun` | Generate synthetic report data with no Azure calls. | switch |
| `-FSLogixStorageAccount` | Explicit FSLogix profile storage account name. | `stfslogixprod` |
| `-FSLogixTagName` | Host pool tag whose value names the FSLogix storage account. | `ProfileStorage` |
| `-FSLogixNamePattern` | Storage account name wildcard for FSLogix discovery. | `*profiles*` |

## FSLogix storage discovery

The FSLogix Region Colocation and Profile Redundancy checks need to identify profile storage. Discovery runs in this order:

1. `-FSLogixStorageAccount` explicit override
2. Host pool tag, default `FSLogixStorageAccount`
3. Storage account name-pattern scan in the host pool resource group, default `*fslogix*`

If storage cannot be discovered, FSLogix-dependent checks return `Info` and explain how to make discovery deterministic.

## JSON, trends, and multi-subscription sweep

`-OutputFormat JSON` or `Both` emits a stable JSON report with environment metadata, category scores, check results, remediation text, and Learn links.

`-CompareTo` annotates the current run with deltas (`▲`, `▼`, `=`), flags checks that are new since the baseline, and lists checks that are no longer assessed.

`-AllAccessibleSubscriptions` assesses every enabled subscription the identity can read, skips inaccessible subscriptions instead of failing the whole run, and writes an `index.html` roll-up plus one report pair per assessed subscription.

## Scoring model

- **Pass** — meets best practice; score 100
- **Warning** — partial gap or moderate risk; score 40–80
- **Fail** — significant risk or missing baseline control; score 0–40
- **Info** — not applicable, not enough data, or missing optional permissions; excluded from category averages

Category scores average non-Info checks. The overall score averages category scores. Categories with partial `Info` results show `X of Y scored` so incomplete evidence is visible.

## Project lineage

- This fork: [marsillig/AVD-Scout](https://github.com/marsillig/AVD-Scout)
- Upstream original: [WayneBellows/AVD-Assess](https://github.com/WayneBellows/AVD-Assess)
- Branding/site link used in generated reports: [https://virtex.cloud](https://virtex.cloud)

## Contributing

Bug reports, check ideas, and report improvements for this fork are welcome in [marsillig/AVD-Scout](https://github.com/marsillig/AVD-Scout). Keep contributions read-only, single-file, and aligned with the existing Az module dependency set.

## License

[MIT](LICENSE) — this fork preserves the upstream MIT license.
