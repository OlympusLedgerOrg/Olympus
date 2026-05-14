param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path,
    [string]$LogPath = (Join-Path $env:TEMP "olympus-native-start.log"),
    [string]$AppUrl = "http://localhost:8000",
    [int]$Port = 8765
)

$ErrorActionPreference = "SilentlyContinue"

function Get-ContentType {
    param([string]$Path)
    switch -Regex ($Path) {
        "\.png$" { "image/png"; break }
        default { "text/plain; charset=utf-8" }
    }
}

function Write-Response {
    param(
        [System.Net.HttpListenerResponse]$Response,
        [byte[]]$Bytes,
        [string]$ContentType,
        [int]$StatusCode = 200
    )

    $Response.StatusCode = $StatusCode
    $Response.ContentType = $ContentType
    $Response.ContentLength64 = $Bytes.Length
    $Response.OutputStream.Write($Bytes, 0, $Bytes.Length)
    $Response.OutputStream.Close()
}

function Test-AppReady {
    try {
        $health = Invoke-WebRequest -Uri "$AppUrl/health" -UseBasicParsing -TimeoutSec 1
        return ($health.StatusCode -ge 200 -and $health.StatusCode -lt 500)
    } catch {
        return $false
    }
}

if (-not (Test-Path $LogPath)) {
    New-Item -ItemType File -Force -Path $LogPath | Out-Null
}

$loadingPng = Join-Path $RepoRoot "app\public-ui\dist\loading.png"
if (-not (Test-Path $loadingPng)) {
    $loadingPng = Join-Path $RepoRoot "app\public-ui\loading.png"
}
if (-not (Test-Path $loadingPng)) {
    $loadingPng = Join-Path $RepoRoot "app\public-ui\public\loading.png"
}

$loadingSrc = "/loading.png"
if (Test-Path $loadingPng) {
    $loadingMime = Get-ContentType $loadingPng
    $loadingBase64 = [Convert]::ToBase64String([System.IO.File]::ReadAllBytes($loadingPng))
    $loadingSrc = "data:$loadingMime;base64,$loadingBase64"
}

$listener = [System.Net.HttpListener]::new()
$bound = $false
foreach ($candidate in $Port..($Port + 10)) {
    try {
        $listener.Prefixes.Clear()
        $listener.Prefixes.Add("http://127.0.0.1:$candidate/")
        $listener.Start()
        $Port = $candidate
        $bound = $true
        break
    } catch {
        continue
    }
}

if (-not $bound) {
    Start-Process $AppUrl
    exit 0
}

Start-Process "http://127.0.0.1:$Port/"

$html = @"
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Olympus Starting</title>
  <style>
    html, body {
      margin: 0;
      width: 100%;
      height: 100%;
      background: #020403;
      color: #00ff66;
      font-family: Consolas, "Cascadia Mono", monospace;
      overflow: hidden;
    }
    body {
      display: grid;
      place-items: center;
    }
    .splash {
      position: fixed;
      inset: 0;
      display: grid;
      place-items: center;
      background:
        radial-gradient(circle at center, rgba(0,255,102,0.12), transparent 46%),
        #020403;
    }
    .splash img {
      width: min(62vw, 720px);
      max-height: 70vh;
      object-fit: contain;
      filter: drop-shadow(0 0 32px rgba(0,255,102,0.25));
    }
    .terminal {
      position: fixed;
      left: 16px;
      right: 16px;
      bottom: 14px;
      min-height: 112px;
      max-height: 22vh;
      border: 1px solid rgba(0,255,102,0.42);
      background: rgba(0, 0, 0, 0.82);
      box-shadow: 0 0 28px rgba(0,255,102,0.16);
      overflow: hidden;
    }
    .bar {
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 7px 10px;
      border-bottom: 1px solid rgba(0,255,102,0.24);
      color: rgba(185,255,210,0.92);
      font-size: 12px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }
    .dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: #00ff66;
      box-shadow: 0 0 14px #00ff66;
      animation: pulse 0.9s infinite alternate;
    }
    pre {
      margin: 0;
      padding: 10px;
      white-space: pre-wrap;
      font-size: 12px;
      line-height: 1.35;
      color: rgba(0,255,102,0.92);
    }
    @keyframes pulse {
      from { opacity: 0.35; }
      to { opacity: 1; }
    }
  </style>
</head>
<body>
  <div class="splash"><img src="$loadingSrc" alt="Olympus loading"></div>
  <section class="terminal" aria-label="Startup progress">
    <div class="bar"><span class="dot"></span><span>PowerShell startup stream</span></div>
    <pre id="log">waiting for Olympus native launcher...</pre>
  </section>
  <script>
    const log = document.getElementById("log");
    async function tick() {
      try {
        const text = await fetch("/log", { cache: "no-store" }).then(r => r.text());
        log.textContent = text || "waiting for Olympus native launcher...";
      } catch {}
      try {
        const ready = await fetch("/ready", { cache: "no-store" }).then(r => r.json());
        if (ready.ready) {
          log.textContent += "\n[ready] opening Olympus console...";
          setTimeout(() => { location.href = ready.appUrl; }, 650);
          return;
        }
      } catch {}
      setTimeout(tick, 650);
    }
    tick();
  </script>
</body>
</html>
"@

$utf8 = [System.Text.Encoding]::UTF8
$deadline = (Get-Date).AddMinutes(10)
while ((Get-Date) -lt $deadline) {
    try {
        $context = $listener.GetContext()
        $requestPath = $context.Request.Url.AbsolutePath

        if ($requestPath -eq "/" -or $requestPath -eq "/index.html") {
            Write-Response -Response $context.Response -Bytes ($utf8.GetBytes($html)) -ContentType "text/html; charset=utf-8"
            continue
        }

        if ($requestPath -eq "/loading.png" -and (Test-Path $loadingPng)) {
            Write-Response -Response $context.Response -Bytes ([System.IO.File]::ReadAllBytes($loadingPng)) -ContentType (Get-ContentType $loadingPng)
            continue
        }

        if ($requestPath -eq "/log") {
            $lines = @()
            if (Test-Path $LogPath) {
                $lines = Get-Content -Path $LogPath -Tail 28
            }
            Write-Response -Response $context.Response -Bytes ($utf8.GetBytes(($lines -join "`n"))) -ContentType "text/plain; charset=utf-8"
            continue
        }

        if ($requestPath -eq "/ready") {
            $ready = Test-AppReady
            $json = (@{ ready = $ready; appUrl = $AppUrl } | ConvertTo-Json -Compress)
            Write-Response -Response $context.Response -Bytes ($utf8.GetBytes($json)) -ContentType "application/json; charset=utf-8"
            if ($ready) {
                Start-Sleep -Seconds 3
                break
            }
            continue
        }

        Write-Response -Response $context.Response -Bytes ($utf8.GetBytes("not found")) -ContentType "text/plain; charset=utf-8" -StatusCode 404
    } catch {
        Start-Sleep -Milliseconds 150
    }
}

$listener.Stop()
