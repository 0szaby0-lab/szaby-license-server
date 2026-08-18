# Szaby License Server

License validation backend for Szaby Patches. Runs on Render.com.

## Setup

1. Push this repo to GitHub
2. Create a new Web Service on render.com linked to this repo
3. Set `ADMIN_TOKEN` environment variable to a strong secret password
4. Access admin panel at `https://your-app.onrender.com/admin`

## API Endpoints

- `GET /api/validate?key=XXX&hwid=YYY` - Validate license key
- `POST /api/report-bypass` - Report bypass attempt (called by client)
- `GET /health` - Health check

## Admin Endpoints (require X-Admin-Token header)

- `POST /admin/keys/generate` - Generate new key
- `GET /admin/keys` - List all keys
- `POST /admin/keys/revoke` - Revoke a key
- `POST /admin/ban` - HWID ban a device
- `POST /admin/unban` - Remove HWID ban
- `GET /admin/logs` - Recent activity logs

