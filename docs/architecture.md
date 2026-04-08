# HomeOps Architektur (MVP)

## Schichten
- Frontend (Next.js App Router, TypeScript, UI/UX Layer)
- Backend (FastAPI, Auth, RBAC, REST APIs, Adapter-Schicht)
- Datenbank (MariaDB + Alembic Migrationen)
- Integrationen (adapter-basiert mit klaren Interfaces)

## Sicherheitsgrundsätze
- Frontend spricht nur mit Backend API.
- Keine API-Tokens im Frontend.
- Rollenmodell: `viewer`, `operator`, `admin`, `superadmin`.
- Audit-Logging für sicherheitsrelevante Events.
- Passwort-Hashing via bcrypt (passlib).
- Struktur für WebAuthn + 2FA Tabellen vorbereitet.

## Erweiterungspunkte
- WebSocket-Live-Metriken/Terminal
- Agenten für Host-Aktionen
- Reale Integrationsadapter (Solar/DDNS/WireGuard/Portainer/Prometheus)
