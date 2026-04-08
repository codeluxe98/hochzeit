# HomeOps Control Center (MVP Foundation)

Produktionsnahes Grundsystem für zentrale Verwaltung von Heimnetzwerk, Raspberry Pis und Hetzner-Servern.

## Stack
- Frontend: Next.js (App Router, TypeScript)
- Backend: FastAPI + SQLModel + Alembic
- DB: MariaDB
- Container: Docker Compose

## Struktur
- `frontend/` UI, Routing, API-Client, Seiten für Dashboard/Server/Users/Audit/Integrationen
- `backend/` API, Auth, RBAC, Datenmodelle, Seeddaten, Adapter-Schnittstellen
- `infra/` Compose und Umgebungsvariablen
- `docs/` Architekturhinweise

## Schnellstart lokal
1. `cp infra/.env.example infra/.env`
2. `cp backend/.env.example backend/.env`
3. `cp frontend/.env.example frontend/.env.local`
4. `cd infra && docker compose up --build`
5. Frontend: `http://localhost:3000`, Backend: `http://localhost:8000/docs`

## Seed Login
- Benutzer: `superadmin`
- Passwort: `ChangeMe!1234`

## MVP enthalten
- Login + JWT
- Dashboard Übersicht
- Server CRUD + Detail + Metrikdaten (Seed)
- Aktionen mit Audit-Log-Eintrag
- Benutzerliste + Rollenänderung API
- Integrations-Adapter-Basis (Solar, DDNS, WireGuard, Portainer, Prometheus)
- DB-Schema + initiale Alembic-Migration

## Hinweise
- WebAuthn/Passkeys + 2FA sind als Datenmodell und Erweiterungspfade vorbereitet; vollständiger Challenge/Verify-Flow folgt im nächsten Ausbau.
- Für Produktion müssen Secrets, TLS, Reverse Proxy, Rate-Limit (z. B. Redis) und harte Sicherheits-Policies ergänzt werden.
