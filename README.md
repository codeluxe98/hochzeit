# Hochzeit

Eine einfache Flask-Anwendung für eine Hochzeitswebseite. Sie ermöglicht RSVP-Antworten, Fotouploads über einen QR-Code und eine Admin-Oberfläche.

## Setup

1. Abhängigkeiten installieren:
   ```bash
   pip install -r requirements.txt
   ```
2. Datenbank konfigurieren. Standardmäßig wird eine lokale SQLite-Datei verwendet. Um MySQL zu nutzen, setze die Umgebungsvariable `DATABASE_URL`, z. B.:
   ```bash
   export DATABASE_URL=mysql://user:pass@localhost/hochzeit
   ```

3. Admin-Benutzer anlegen:
   ```bash
   python create_admin.py
   ```

4. Anwendung starten (für Zugriff von anderen Geräten `--host 0.0.0.0` verwenden):
   ```bash
   flask --app app run --host 0.0.0.0
   ```

## Tests

```bash
pytest
```
