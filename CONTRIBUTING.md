# Contributing to AVD-Assess

Thanks for your interest in improving AVD-Assess. This is a single-file PowerShell tool by design — contributions should preserve that simplicity.

## Adding a new check

Every check lives inside `AVD-Assess.ps1` and registers its outcome by calling `Add-CheckResult`. Display name, remediation, and Learn URL are **not** inlined at the call site — they live once in the `$script:CheckCatalog` hashtable, keyed by a stable check ID, and are read by both the real check and the dry-run seeder. Adding a check is a three-step sequence:

1. **Register it in `$script:CheckCatalog`** under a new ID (e.g. `ScalingPlanCoverage`) with `Name`, `Remediation`, and `LearnMore`.
2. **Write the check function**, calling `Add-CheckResult` and pulling the catalogued strings:

   ```powershell
   Add-CheckResult `
       -Category    'Cost' `                                       # Cost | Reliability | Security | Operations | Performance
       -CheckName   $script:CheckCatalog.ScalingPlanCoverage.Name `
       -Status      'Pass' `                                        # Pass | Warning | Fail | Info
       -Score       100 `                                           # 0-100; Info checks always 100, excluded from averages
       -Finding     'What was found, with specific counts / names.' `
       -Remediation $script:CheckCatalog.ScalingPlanCoverage.Remediation `
       -LearnMore   $script:CheckCatalog.ScalingPlanCoverage.LearnMore
   ```
3. **Seed it in `Initialize-DryRunData`** so `-DryRun` renders a synthetic result for the new check.

The catalog ID also becomes the check's stable `id` in JSON output and the key `-CompareTo` matches on across runs — so keep IDs stable once shipped (renaming an ID makes the check look "new" and the old one "no longer assessed" in a diff). A new check is automatically additive to the JSON schema; only bump `$script:JsonSchemaVersion` (minor for additive envelope fields, major for removals/renames) if you change the JSON *structure*, not when adding a check.

Rules of thumb for new checks:

- **Be specific in findings.** Name the affected host pool / VM / session host. Counts and percentages beat adjectives.
- **Be actionable in remediation.** A reader should be able to fix the problem without a second search. Quote the exact property, cmdlet, or portal blade.
- **Link to Microsoft Learn**, not a blog. If no Learn article exists, link the closest official Azure doc.
- **Score proportionally** where possible (e.g. % of hosts compliant). Reserve Fail < 40 for material risk.
- **Use `Info` sparingly** — it's for checks that don't apply to the environment (e.g. no personal host pools) or are educational-only (e.g. load-balancing algorithm review). `Info` checks are excluded from category averages.
- **Read from the pre-collected script-scoped data** (`$script:allHostPools`, `$script:allSessionHosts`, etc.) rather than making fresh Azure calls inside the check.

## Testing a change

1. **Parse-check the script locally:**
   ```powershell
   [System.Management.Automation.Language.Parser]::ParseFile(
       "$PWD\AVD-Assess.ps1", [ref]$null, [ref]$null
   ) | Out-Null
   ```
2. **Render the HTML offline** using the hidden dry-run switch:
   ```powershell
   ./AVD-Assess.ps1 -DryRun -OutputPath ./_dryrun.html -OpenReport
   ```
   This seeds synthetic results for all 25 checks and produces a full report without hitting Azure. Useful for verifying UI changes and new categories/statuses. Add `-OutputFormat Both` to also exercise the JSON writer, and `-CompareTo <previous.json>` to verify delta rendering.
3. **Run against a real subscription** with a varied configuration (mix of pooled / personal, scaling plans present / absent, healthy / unhealthy hosts). Ideally a dev subscription — this tool is read-only but you should still scope carefully.

## Pull request guidelines

- **One check or one self-contained improvement per PR.** Easier to review, easier to revert.
- **Include test evidence** — a screenshot of the new report section, or the relevant console output.
- **Explain the Pass / Warning / Fail thresholds** in the PR description, especially for any proportional scoring.
- **Match the existing style** — 4-space indentation, `Verb-Noun` function names, comment-based help on functions, banner comments separating major sections.
- **No new module dependencies** beyond the eight Az modules already required (`Az.Accounts`, `Az.DesktopVirtualization`, `Az.Compute`, `Az.Monitor`, `Az.Resources`, `Az.Network`, `Az.Storage`, `Az.Security`).
- **Keep the single-file structure.** Do not split into modules, dot-sourced files, or sub-folders.

## Reporting issues

Open an issue on GitHub with:

- PowerShell version (`$PSVersionTable.PSVersion`)
- Az module versions (`Get-Module Az.* -ListAvailable | Select Name, Version`)
- The full console output (redact any subscription or tenant IDs)
- Whether the problem is reproducible against a different subscription

## Licence

By contributing you agree that your work is licensed under the MIT licence of this project.
