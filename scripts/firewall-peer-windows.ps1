#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Lock Olympus ports to Tailscale peers only.

.DESCRIPTION
    Locks Olympus network exposure down to a single advertised ingress:
      - Port 22   (SSH/OpenSSH)  — Tailscale subnet only; the ONLY advertised ingress
                                   (transport for the API tunnel)
      - Port 8001 (Olympus API)  — no firewall rule; app binds 127.0.0.1 only and is
                                   reached over the SSH tunnel, not directly
      - Port 5433 (Postgres)     — BLOCKED from the network; each host keeps its own
                                   local DB (never tunneled)

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
# Port 22 is the only advertised ingress; the API (8001) binds loopback and is
# reached via the SSH tunnel, so NO 8001 allow rule is added. Before applying,
# the script disables any pre-existing broader allow rules on 22 and 8001 so
# none of them bypass the restriction (8001 is kept fully closed to inbound).
$RULES = @(
    @{
        Name        = "Olympus-SSH-Tailscale-Inbound"
        DisplayName = "Olympus SSH tunnel (Tailscale peers only)"
        Port        = 22
        Protocol    = "TCP"
        RemoteAddr  = $TAILSCALE_SUBNET
        Description = "Allow Tailscale peers to SSH in to tunnel the Olympus API (port 8001)."
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

# Old rule names removed on upgrade:
#   - Olympus-Postgres-Block-All     — pre-IPv6-fix single Postgres block rule
#   - Olympus-API-Tailscale-Inbound  — port-8001 allow rule; dropped now that the API
#                                      binds loopback only and is reached via the SSH
#                                      tunnel (port 22 is the only ingress).
$LEGACY_RULE_NAMES = @("Olympus-Postgres-Block-All", "Olympus-API-Tailscale-Inbound")

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
    traffic, because Windows Firewall falls through to Allow if any matching
    Allow rule exists. For port 22 we replace them with a Tailscale-only allow;
    for 8001 we add no allow rule at all (the API binds loopback), so disabling
    any stray 8001 allow keeps that port fully closed to inbound traffic.
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

    # Scoped-key expiry: 90-day rolling window, ISO 8601 UTC as /key/admin/generate expects.
    $ExpiryDate = (Get-Date).ToUniversalTime().AddDays(90).ToString("yyyy-MM-ddTHH:mm:ss'Z'")

    Write-Host @"

Firewall rules applied.

PORTS SUMMARY
  22    SSH           — Tailscale peers only  ($TAILSCALE_SUBNET)  ← the ONLY ingress
  8001  Olympus API   — no firewall rule; loopback-only, reached via the SSH tunnel below
  5433  Postgres      — BLOCKED from network (each host keeps its OWN local DB)

MODEL
  Every machine runs its own Olympus node + local Postgres. Yours is the shared
  "server"; your buddy reaches its API over an SSH tunnel. The Axum server binds
  127.0.0.1 only and 403s any non-localhost Host (by design, audit M-6 / M-API-1),
  so port 8001 is NOT directly reachable over Tailscale — the tunnel is the path.

NEXT STEPS
  1. Enable OpenSSH Server if not already:
       Settings → Apps → Optional features → Add "OpenSSH Server"
       Set-Service sshd -StartupType Automatic; Start-Service sshd

  2. Share your Tailscale IP with your buddy:
       tailscale ip

  3. Your buddy tunnels your API port to a free local port (on his Mac):
       # One-time: add your host key
       ssh-keyscan <your-tailscale-ip> >> ~/.ssh/known_hosts

       # Open the tunnel (keep this terminal open). Local 18001 avoids clashing
       # with his own node if he also runs one on 8001:
       ssh -N -L 18001:localhost:8001 <your-windows-username>@<your-tailscale-ip>

       # Your server's API is now at http://localhost:18001 on his machine.
       # He MUST keep the host as "localhost" — the server 403s any other Host.

  4. His own node + DB (optional — for his local work):
       cargo tauri dev      # or his built Olympus binary; gets its own embedded
                            # Postgres automatically — nothing to share or tunnel.

  5. Mint him a scoped key on your machine (needs `$env:OLYMPUS_ADMIN_KEY set),
     or use the desktop app's Users tab:
       Invoke-RestMethod -Method Post http://localhost:8001/key/admin/generate -Headers @{ 'x-admin-key' = `$env:OLYMPUS_ADMIN_KEY } -ContentType 'application/json' -Body '{"name":"buddy","scopes":["ingest","read","verify"],"expires_at":"$ExpiryDate"}'
       # Returns raw_key — he sends it as the  X-API-Key  header to http://localhost:18001.
       # Also returns env_entry — register it (OLYMPUS_API_KEYS_JSON or the Users tab) to activate the key.

"@ -ForegroundColor Cyan
}

if ($Remove) {
    Remove-OlympusRules
} else {
    Write-Host "`nApplying Olympus firewall rules..." -ForegroundColor Cyan
    Add-OlympusRules
}
