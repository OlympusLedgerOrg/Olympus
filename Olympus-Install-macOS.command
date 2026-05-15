#!/usr/bin/env bash
# Finder double-click installer for the Olympus local production package.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${REPO_ROOT}"
LOG_DIR="${REPO_ROOT}/.olympus-logs"
START_LOG="${LOG_DIR}/package-start.log"
SPLASH_HTML="${LOG_DIR}/package-splash.html"
COMPOSE=(docker compose -f docker-compose.package.yml)

log() {
    printf '[olympus] %s\n' "$*"
}

fail() {
    printf '\n[olympus] ERROR: %s\n' "$*" >&2
    printf '[olympus] Press Return to close this window.\n' >&2
    read -r _ || true
    exit 1
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

write_start_log() {
    mkdir -p "${LOG_DIR}"
    printf '[%s] %s\n' "$(date '+%H:%M:%S')" "$*" >> "${START_LOG}"
}

open_splash() {
    mkdir -p "${LOG_DIR}"
    : > "${START_LOG}"
    write_start_log "OLYMPUS_PROTOCOL package installer opened."
    write_start_log "Loading splash art and Docker startup progress."

    cat > "${SPLASH_HTML}" <<EOF
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Olympus Starting</title>
  <style>
    html, body { margin: 0; width: 100%; height: 100%; background: #020403; color: #00ff66; font-family: Menlo, Monaco, monospace; overflow: hidden; }
    body { display: grid; place-items: center; }
    .splash { position: fixed; inset: 0; display: grid; place-items: center; background: radial-gradient(circle at center, rgba(0,255,102,0.12), transparent 46%), #020403; }
    .splash img { width: min(96vw, 1600px); max-height: calc(100vh - 150px); object-fit: contain; filter: drop-shadow(0 0 32px rgba(0,255,102,0.25)); }
    .terminal { position: fixed; left: 16px; right: 16px; bottom: 14px; min-height: 112px; max-height: 22vh; border: 1px solid rgba(0,255,102,0.42); background: rgba(0,0,0,0.82); box-shadow: 0 0 28px rgba(0,255,102,0.16); overflow: hidden; }
    .bar { display: flex; align-items: center; gap: 10px; padding: 7px 10px; border-bottom: 1px solid rgba(0,255,102,0.24); color: rgba(185,255,210,0.92); font-size: 12px; letter-spacing: 0.08em; text-transform: uppercase; }
    .dot { width: 8px; height: 8px; border-radius: 50%; background: #00ff66; box-shadow: 0 0 14px #00ff66; animation: pulse 0.9s infinite alternate; }
    pre { margin: 0; padding: 10px; white-space: pre-wrap; font-size: 12px; line-height: 1.35; color: rgba(0,255,102,0.92); }
    @keyframes pulse { from { opacity: 0.35; } to { opacity: 1; } }
  </style>
</head>
<body>
  <div class="splash"><img src="../app/public-ui/loading.png" alt="Olympus loading"></div>
  <section class="terminal" aria-label="Startup progress">
    <div class="bar"><span class="dot"></span><span>Docker Desktop startup stream</span></div>
    <pre id="log">starting Olympus package...</pre>
  </section>
  <script>
    const target = "http://127.0.0.1:8080";
    const health = "http://127.0.0.1:8080/healthz";
    const log = document.getElementById("log");
    let ticks = 0;
    async function poll() {
      ticks += 1;
      log.textContent = "starting Olympus package...\\nwaiting for Docker services";
      log.textContent += ".".repeat(ticks % 4);
      try {
        await fetch(health, { cache: "no-store", mode: "no-cors" });
        log.textContent += "\\n[ready] opening Olympus console...";
        setTimeout(() => { location.href = target; }, 650);
        return;
      } catch {}
      setTimeout(poll, 1000);
    }
    poll();
  </script>
</body>
</html>
EOF
    open "${SPLASH_HTML}" >/dev/null 2>&1 || true
}

wait_for_url() {
    local name="$1"
    local url="$2"
    local attempts="$3"
    local i

    log "Waiting for ${name} at ${url}..."
    for i in $(seq 1 "${attempts}"); do
        if curl -fsS --max-time 2 "${url}" >/dev/null 2>&1; then
            log "${name} is healthy."
            return 0
        fi
        sleep 2
    done
    return 1
}

echo
echo "Olympus local production package"
echo "================================================================"
echo "This will bootstrap secrets, build containers, start Docker"
echo "Compose, wait for health checks, then open the UI."
echo

open_splash

command_exists docker || {
    open "https://www.docker.com/products/docker-desktop/" >/dev/null 2>&1 || true
    fail "Docker Desktop is not installed or docker is not on PATH. Install Docker Desktop, start it once, then run this again."
}

command_exists curl || fail "curl was not found."

log "Bootstrapping .env and secrets..."
write_start_log "[1/5] Bootstrap starting."
bash "${REPO_ROOT}/scripts/bootstrap.sh"
write_start_log "[1/5] Bootstrap complete."

if ! docker info >/dev/null 2>&1; then
    log "Docker is installed but not running. Starting Docker Desktop..."
    write_start_log "[2/5] Starting Docker Desktop."
    open -a Docker >/dev/null 2>&1 || fail "Could not start Docker Desktop. Open it manually, then run this again."

    log "Waiting for Docker engine..."
    for _ in $(seq 1 90); do
        if docker info >/dev/null 2>&1; then
            break
        fi
        sleep 2
    done
fi

docker info >/dev/null 2>&1 || fail "Docker Desktop did not become ready. Open Docker Desktop and resolve any setup prompts, then run this again."
log "Docker is ready."
write_start_log "[2/5] Docker is ready."

log "Checking for an already-running Olympus package..."
write_start_log "[2b/5] Checking for an already-running Olympus package."
if curl -fsS --max-time 2 "http://127.0.0.1:8080/healthz" >/dev/null 2>&1; then
    log "Olympus UI is already running at http://127.0.0.1:8080"
    write_start_log "Existing Olympus UI is healthy. Reusing it."
    open "http://127.0.0.1:8080" >/dev/null 2>&1 || true
    printf '[olympus] Press Return to close this window. Olympus is already running in Docker.\n'
    read -r _ || true
    exit 0
fi

if [ "$(docker ps --filter "name=olympus-package-" --format "{{.Names}}" | wc -l | tr -d ' ')" != "0" ]; then
    log "Found existing Olympus package containers. Reusing/updating them."
    write_start_log "Found existing Olympus package containers; compose will reuse/update them."
fi

log "Building and starting Olympus. First run can take several minutes..."
write_start_log "[3/5] docker compose up -d --build starting. First run can take several minutes."
"${COMPOSE[@]}" up -d --build --remove-orphans || {
    "${COMPOSE[@]}" logs --tail=200 >&2 || true
    fail "Docker Compose failed."
}
write_start_log "[3/5] Docker Compose returned successfully."

write_start_log "[4/5] Waiting for API health at http://127.0.0.1:8001/health."
wait_for_url "API" "http://127.0.0.1:8001/health" 90 || {
    "${COMPOSE[@]}" logs app >&2 || true
    fail "API did not become healthy."
}
write_start_log "[4/5] API is healthy."

write_start_log "[5/5] Waiting for UI health at http://127.0.0.1:8080/healthz."
wait_for_url "UI" "http://127.0.0.1:8080/healthz" 60 || {
    "${COMPOSE[@]}" logs public-ui >&2 || true
    fail "UI did not become healthy."
}
write_start_log "[5/5] UI is healthy. Opening Olympus."

open "http://127.0.0.1:8080" >/dev/null 2>&1 || true

echo
echo "Olympus is live."
echo "------------------------------------------------"
echo "UI:        http://127.0.0.1:8080"
echo "API:       http://127.0.0.1:8001"
echo "Stop:      docker compose -f docker-compose.package.yml down"
echo "Logs:      docker compose -f docker-compose.package.yml logs -f"
echo
printf '[olympus] Press Return to close this window. Olympus keeps running in Docker.\n'
read -r _ || true
