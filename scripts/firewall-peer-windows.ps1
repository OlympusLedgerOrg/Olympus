#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Lock Olympus ports to Tailscale peers only.

.DESCRIPTION
    Adds Windows Firewall rules so that:
      - Port 8001 (Olympus API)  — Tailscale subnet only (100.64.0.0/10)
      - Port 5433 (Postgres)     — localhost only (SSH tunnel; no direct network access)
      - Port 22   (SSH/OpenSSH)  — Tailscale subnet only (for DB tunnel)

    Run once before giving your buddy the Tailscale IP.
    Run with -Remove to tear all rules down.

.EXAMPLE
    # Lock ports (run as Administrator):
    powershell -ExecutionPolicy Bypass -File scripts\firewall-peer-windows.ps1

    # Remove rules:
    powershell -ExecutionPolicy Bypass -File scripts\firewall-peer-windows.ps1 -Remove
#>

param([switch]$Remove)

$TAILSCALE_SUBNET = "100.64.0.0/10"   # All Tailscale nodes worldwide

# Rules that restrict inbound access to Tailscale peers.
# Before adding these, the script disables any pre-existing broader allow
# rules on ports 22 and 8001 so that those don't bypass the restriction.
$RULES = @(
    @{
        Name        = "Olympus-API-Tailscale-Inbound"
        DisplayName = "Olympus API (Tailscale peers only)"
        Port        = 8001
        Protocol    = "TCP"
        RemoteAddr  = $TAILSCALE_SUBNET
        Description = "Allow Tailscale peers to reach the Olympus API. Blocks all other sources."
    },
    @{
        Name        = "Olympus-SSH-Tailscale-Inbound"
        DisplayName = "Olympus SSH tunnel (Tailscale peers only)"
        Port        = 22
        Protocol    = "TCP"
        RemoteAddr  = $TAILSCALE_SUBNET
        Description = "Allow Tailscale peers to SSH in for the Postgres tunnel."
    },
    # IPv4 block
    @{
        Name        = "Olympus-Postgres-Block-All-IPv4"
        DisplayName = "Olympus Postgres (BLOCK non-localhost IPv4)"
        Port        = 5433
        Protocol    = "TCP"
        RemoteAddr  = "0.0.0.0/0"
        Action      = "Block"
        Description = "Postgres must never be directly reachable from the network (IPv4)."
    },
    # IPv6 block — separate rule required; 0.0.0.0/0 only matches IPv4
    @{
        Name        = "Olympus-Postgres-Block-All-IPv6"
        DisplayName = "Olympus Postgres (BLOCK non-localhost IPv6)"
        Port        = 5433
        Protocol    = "TCP"
        RemoteAddr  = "::/0"
        Action      = "Block"
        Description = "Postgres must never be directly reachable from the network (IPv6)."
    }
)

# Names of the old single-entry Postgres block rule (pre-IPv6 fix) — removed on upgrade.
$LEGACY_RULE_NAMES = @("Olympus-Postgres-Block-All")

function Remove-OlympusRules {
    # Remove current rules
    foreach ($rule in $RULES) {
        $existing = Get-NetFirewallRule -Name $rule.Name -ErrorAction SilentlyContinue
        if ($existing) {
            Remove-NetFirewallRule -Name $rule.Name
            Write-Host "  Removed: $($rule.DisplayName)" -ForegroundColor Yellow
        }
    }
    # Remove legacy single-rule names from before the IPv6 fix
    foreach ($legacyName in $LEGACY_RULE_NAMES) {
        $existing = Get-NetFirewallRule -Name $legacyName -ErrorAction SilentlyContinue
        if ($existing) {
            Remove-NetFirewallRule -Name $legacyName
            Write-Host "  Removed legacy rule: $legacyName" -ForegroundColor Yellow
        }
    }
    Write-Host "`nAll Olympus firewall rules removed." -ForegroundColor Cyan
}

function Disable-ConflictingAllowRules {
    <#
    .SYNOPSIS
        Disable pre-existing inbound Allow rules on ports 22 and 8001.

    Pre-existing broader allow rules (e.g. the Windows default OpenSSH allow
    rule that matches Any remote address) would still match non-Tailscale
    traffic even after the Olympus Tailscale-only rules are added, because
    Windows Firewall evaluates more-specific Allow rules first but falls
    through to Allow if any matching Allow rule exists.  Disabling the
    conflicting rules ensures only Tailscale peers can connect.
    #>
    $conflictPorts = @(22, 8001)
    $olympusNames  = $RULES | ForEach-Object { $_.Name }

    foreach ($port in $conflictPorts) {
        $portFilter = Get-NetFirewallPortFilter | Where-Object {
            $_.LocalPort -eq $port -and $_.Protocol -eq "TCP"
        }
        foreach ($pf in $portFilter) {
            $rule = $pf | Get-NetFirewallRule | Where-Object {
                $_.Direction -eq "Inbound" -and
                $_.Action    -eq "Allow"   -and
                $_.Enabled   -eq "True"    -and
                $_.Name -notin $olympusNames
            }
            foreach ($r in $rule) {
                Disable-NetFirewallRule -Name $r.Name
                Write-Host "  Disabled conflicting allow rule: '$($r.DisplayName)' (port $port)" `
                    -ForegroundColor Yellow
            }
        }
    }
}

function Add-OlympusRules {
    # Remove legacy single-entry Postgres block rule if present
    foreach ($legacyName in $LEGACY_RULE_NAMES) {
        Remove-NetFirewallRule -Name $legacyName -ErrorAction SilentlyContinue
    }

    # Disable any pre-existing broader Allow rules on ports 22/8001 so they
    # cannot bypass the Tailscale-only restriction we're about to add.
    Disable-ConflictingAllowRules

    foreach ($rule in $RULES) {
        # Remove stale version first
        Remove-NetFirewallRule -Name $rule.Name -ErrorAction SilentlyContinue

        $action = if ($rule.Action) { $rule.Action } else { "Allow" }
        $color  = if ($action -eq "Block") { "Red" } else { "Green" }

        New-NetFirewallRule `
            -Name          $rule.Name `
            -DisplayName   $rule.DisplayName `
            -Description   $rule.Description `
            -Direction     Inbound `
            -Protocol      $rule.Protocol `
            -LocalPort     $rule.Port `
            -RemoteAddress $rule.RemoteAddr `
            -Action        $action `
            -Profile       Any `
            -Enabled       True | Out-Null

        Write-Host "  [$action] $($rule.DisplayName)  port=$($rule.Port)  from=$($rule.RemoteAddr)" `
            -ForegroundColor $color
    }

    Write-Host @"

Firewall rules applied.

PORTS SUMMARY
  8001  Olympus API   — Tailscale peers only  ($TAILSCALE_SUBNET)
  5433  Postgres      — BLOCKED from network  (localhost / SSH tunnel only)
  22    SSH           — Tailscale peers only  ($TAILSCALE_SUBNET)

NEXT STEPS
  1. Enable OpenSSH Server if not already:
       Settings → Apps → Optional features → Add "OpenSSH Server"
       Set-Service sshd -StartupType Automatic; Start-Service sshd

  2. Share your Tailscale IP with your buddy:
       tailscale ip

  3. Your buddy connects (on his Mac):
       # One-time: add your host key
       ssh-keyscan <your-tailscale-ip> >> ~/.ssh/known_hosts

       # Open the tunnel (keep this terminal open):
       ssh -N -L 5433:localhost:5433 <your-windows-username>@<your-tailscale-ip>

       # In another terminal, start his node:
       uvicorn api.main:app --host 0.0.0.0 --port 8000

  4. His DATABASE_URL should be:
       postgresql+asyncpg://olympus:<password>@localhost:5433/olympus
       (localhost — because the tunnel makes it local on his end)

  5. Generate him a scoped API key (run on your machine):
       python scripts/create_key.py --scope ingest,read,verify --expires 2026-12-31

"@ -ForegroundColor Cyan
}

if ($Remove) {
    Remove-OlympusRules
} else {
    Write-Host "`nApplying Olympus firewall rules..." -ForegroundColor Cyan
    Add-OlympusRules
}
