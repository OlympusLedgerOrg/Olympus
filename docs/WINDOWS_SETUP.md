# Windows PowerShell Setup Guide

## Prerequisites

- Docker Desktop for Windows
- PowerShell 5.1 or later

## Quick Start

1. **Copy environment file:**
   ```powershell
   Copy-Item .env.example .env
   ```

2. **Start services:**
   ```powershell
   docker-compose down -v  # Clean start
   docker-compose up -d
   ```

3. **Check status:**
   ```powershell
   # Check health (use curl.exe, not PowerShell's curl alias)
   curl.exe http://localhost:8000/health

   # Should show: {"status":"ok","database":"connected"}
   ```

4. **Access UI:**
   - API Docs: http://localhost:8000/docs
   - UI: http://localhost:8080

## Troubleshooting

### Database Not Initialized

Check logs:
```powershell
docker-compose logs app
```

Manually run migrations:
```powershell
docker-compose exec app python -m alembic upgrade head
```

### PowerShell curl Warning

PowerShell aliases `curl` to `Invoke-WebRequest`. Use `curl.exe` instead:
```powershell
# Wrong (PowerShell warning)
curl http://localhost:8000/health

# Right (actual curl)
curl.exe http://localhost:8000/health
```

Or use `Invoke-WebRequest`:
```powershell
Invoke-WebRequest -Uri http://localhost:8000/health -UseBasicParsing
```

### UI Not Loading

The UI is now always enabled by default — no environment variable is needed.
If you want to protect it with a password, set `OLYMPUS_DEBUG_CONSOLE_PASSWORD` in your `.env` file.
