# Hochzeit Webapp (PHP + MySQL)

Elegante Hochzeits‑Website mit:
- One‑Pager (Story, Ablauf, Anreise, Unterkunft, Registry, RSVP)
- QR‑geschützter Galerie inkl. Master‑Key (`gallery.php`)
- Foto‑Upload mit Multi‑Upload per Drag & Drop inkl. Fortschrittsbalken pro Bild (`upload.php`)
- Lokaler Speicherung + optionalem Synology File‑Station Upload (pro Gast eigener Ordner auf Basis Vorname/Nachname)
- Gast-spezifischen Synology-Ordnern (pro Gast eigener Upload-Pfad)
- Admin‑Panel für Gäste, QR‑Codes, QR‑Mailversand via SMTP, Foto‑Moderation, Theme‑/Inhalts‑Settings, System/Synology‑Settings, SQL‑Editor und Logs/Statistik (`admin.php`)
- Vollständigem Activity Logging (`activity_logs`)

## Dateien
- `index.php`
- `config.php`
- `gallery.php`
- `upload.php`
- `admin.php`
- `css/style.css`
- `js/scripts.js`
- `schema.sql`

## Installation
1. Abhängigkeiten installieren (QR‑Bibliothek):
```bash
composer require chillerlan/php-qrcode
```
Optional (Legacy‑Variante, ebenfalls unterstützt):
```bash
composer require phpqrcode/phpqrcode
```

2. Datenbank anlegen und Schema importieren:
```bash
mysql -u root -p < schema.sql
```

3. Initialen Admin konfigurieren (wird automatisch erstellt, wenn `users` leer ist):
- `ADMIN_INITIAL_USERNAME`
- `ADMIN_INITIAL_PASSWORD`
- Beim ersten Login muss dieser Admin zwingend E‑Mail und Passwort ändern.

4. `.env` bearbeiten (Datei liegt im Projektroot und wird automatisch von `config.php` geladen):
```dotenv
APP_URL=http://localhost:8080

DB_HOST=127.0.0.1
DB_NAME=wedding_app
DB_USER=root
DB_PASS=

ADMIN_INITIAL_USERNAME=admin
ADMIN_INITIAL_PASSWORD=AdminStart!2026

# Optional: Synology Upload (Fallback; kann auch im Admin unter \"System\" in MySQL gespeichert werden)
SYNO_BASE_URL=https://deine-nas:5001
SYNO_USERNAME=dein-benutzer
SYNO_PASSWORD=dein-passwort
SYNO_TARGET_PATH=/wedding-uploads
SYNO_VERIFY_SSL=1

# Optionaler Fallback für Master-Key (wenn nicht in settings vorhanden)
GALLERY_MASTER_KEY=
```

5. Schreibrechte sicherstellen:
- `uploads/`
- `qrcodes/`

6. Lokal starten (Beispiel):
```bash
php -S 0.0.0.0:8080
```
Dann im Browser öffnen: `http://localhost:8080/index.php`

## Hinweise
- Alle DB‑Zugriffe laufen über prepared statements.
- Admin‑Login nutzt `password_verify()`.
- First‑Login‑Pflicht: Ohne gesetzte E‑Mail oder bei `must_change_password=1` wird zuerst ein Setup‑Formular erzwungen.
- Synology-Konfiguration kann im Admin-Panel gespeichert werden (`settings`-Tabelle) und überschreibt `.env`.
- E-Mail-Vorlagen + SMTP-Zugangsdaten (Host/Port/Encryption/User/Passwort) werden im Admin gespeichert (`settings`) und beim QR-Erstellen automatisch verwendet.
- Galerie-Master-Key wird automatisch mit 32 Zeichen (inkl. Buchstaben, Zahlen, Sonderzeichen) erzeugt und in MySQL gespeichert.
- SQL-Editor im Admin erlaubt direkte Bearbeitung aller MySQL-Inhalte.
- Logs & Statistik sind im Admin-Tab `Logs & Statistik` sichtbar.
- Token‑Zugriff zur Galerie wird serverseitig geprüft (aktiv + nicht abgelaufen). Master-Key ermöglicht Gesamtzugriff.
- Galerie zeigt Uploads ohne Freigabe; Status im Admin steuert nur die Sichtbarkeit auf der öffentlichen Startseite.
- QR-Erzeugung nutzt bei fehlendem `ext-gd` automatisch SVG-Fallback (wenn `chillerlan/php-qrcode` installiert ist).
