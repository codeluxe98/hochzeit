-- --------------------------------------------------------
-- Wedding App Schema (MySQL 8+)
-- --------------------------------------------------------
-- Execute this schema in the database configured by DB_NAME in .env.

CREATE TABLE IF NOT EXISTS users (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(80) NOT NULL UNIQUE,
    email VARCHAR(190) DEFAULT NULL,
    password_hash VARCHAR(255) NOT NULL,
    must_change_password TINYINT(1) NOT NULL DEFAULT 1,
    role ENUM('admin') NOT NULL DEFAULT 'admin',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_users_email (email)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS guests (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    first_name VARCHAR(120) NOT NULL,
    last_name VARCHAR(120) NOT NULL,
    email VARCHAR(190) NOT NULL,
    phone VARCHAR(60) DEFAULT NULL,
    rsvp_status ENUM('offen', 'zugesagt', 'abgesagt') NOT NULL DEFAULT 'offen',
    plus_one TINYINT UNSIGNED NOT NULL DEFAULT 0,
    dietary_notes VARCHAR(255) DEFAULT NULL,
    notes TEXT DEFAULT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_guests_email (email),
    KEY idx_guests_lastname (last_name)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS qr_tokens (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    guest_id INT UNSIGNED NOT NULL,
    token VARCHAR(128) NOT NULL,
    qr_path VARCHAR(255) DEFAULT NULL,
    expires_at DATETIME DEFAULT NULL,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_qr_token (token),
    KEY idx_qr_guest (guest_id),
    CONSTRAINT fk_qr_guest FOREIGN KEY (guest_id) REFERENCES guests(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS photos (
    id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    guest_id INT UNSIGNED DEFAULT NULL,
    token_id INT UNSIGNED DEFAULT NULL,
    original_name VARCHAR(255) NOT NULL,
    file_path VARCHAR(255) NOT NULL,
    synology_path VARCHAR(255) DEFAULT NULL,
    mime_type VARCHAR(80) NOT NULL,
    size_bytes BIGINT UNSIGNED NOT NULL,
    status ENUM('pending', 'approved', 'rejected') NOT NULL DEFAULT 'pending',
    uploaded_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    approved_at TIMESTAMP NULL DEFAULT NULL,
    KEY idx_photos_status (status),
    KEY idx_photos_guest (guest_id),
    KEY idx_photos_token (token_id),
    CONSTRAINT fk_photos_guest FOREIGN KEY (guest_id) REFERENCES guests(id) ON DELETE SET NULL,
    CONSTRAINT fk_photos_token FOREIGN KEY (token_id) REFERENCES qr_tokens(id) ON DELETE SET NULL
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS settings (
    setting_key VARCHAR(120) PRIMARY KEY,
    setting_value TEXT NOT NULL,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS activity_logs (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    event_type VARCHAR(80) NOT NULL,
    message VARCHAR(255) NOT NULL,
    context_json LONGTEXT DEFAULT NULL,
    ip_address VARCHAR(64) DEFAULT NULL,
    user_agent VARCHAR(255) DEFAULT NULL,
    user_id INT UNSIGNED DEFAULT NULL,
    guest_id INT UNSIGNED DEFAULT NULL,
    token_id INT UNSIGNED DEFAULT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    KEY idx_activity_event (event_type),
    KEY idx_activity_created (created_at),
    KEY idx_activity_user (user_id),
    KEY idx_activity_guest (guest_id)
) ENGINE=InnoDB;

INSERT INTO settings (setting_key, setting_value) VALUES
('bride_name', 'Lena'),
('groom_name', 'Jonas'),
('hero_title', 'Wir sagen Ja'),
('wedding_date', '2026-08-15 14:30:00'),
('venue_name', 'Gut Sonnenhof'),
('venue_address', 'Sonnenweg 12, 50667 Köln'),
('intro_text', 'Wir freuen uns auf einen unvergesslichen Tag mit euch voller Musik, Leichtigkeit und ganz viel Liebe.'),
('story_text_1', 'Gestartet mit einem Espresso im Sommerregen, weitergegangen mit tausend kleinen Abenteuern. Zwischen Bahnsteigen, Sonntagsfrühstück und spontanen Roadtrips ist aus „wir schauen mal“ längst „für immer" geworden.'),
('story_text_2', 'Am 15. August feiern wir diesen nächsten Schritt mit den Menschen, die uns am wichtigsten sind: euch.'),
('timeline_1_time', '14:30'),
('timeline_1_title', 'Freie Trauung'),
('timeline_1_text', 'Im Rosengarten unter alten Linden. Taschentücher sind eingeplant.'),
('timeline_2_time', '16:00'),
('timeline_2_title', 'Empfang & Fotospots'),
('timeline_2_text', 'Sekt, feine Häppchen und Zeit für gemeinsame Erinnerungsfotos.'),
('timeline_3_time', '18:30'),
('timeline_3_title', 'Dinner'),
('timeline_3_text', 'Regional, saisonal und mit vegetarischen sowie veganen Optionen.'),
('timeline_4_time', '21:00'),
('timeline_4_title', 'Party'),
('timeline_4_text', 'Eröffnungstanz, Live‑Band und danach DJ bis tief in die Nacht.'),
('travel_train_text', 'Bis Köln Hbf, von dort Shuttle um 13:45 und 14:10 Uhr.'),
('travel_car_text', 'Vor Ort stehen ausgeschilderte Parkplätze zur Verfügung.'),
('travel_nav_address', 'Sonnenweg 12, 50667 Köln'),
('dresscode', 'Summer Chic'),
('stays_intro', 'Wir haben Zimmerkontingente bis zum 01.07.2026 reserviert:'),
('stay_option_1', 'Hotel Gartenblick (8 Min.) – Stichwort „Lena & Jonas“'),
('stay_option_2', 'Rhein Suites (12 Min.) – Shuttle um 01:00 und 02:00 Uhr'),
('stay_option_3', 'Landhaus Bellevue (15 Min.) – ideal für Familien'),
('gift_text_1', 'Eure Anwesenheit ist das größte Geschenk. Wenn ihr uns zusätzlich eine Freude machen möchtet, unterstützen wir gerne unseren Flitterwochen‑Fonds für Portugal.'),
('gift_text_2', 'Vor Ort gibt es eine kleine Wunschbox für Karten und persönliche Nachrichten.'),
('playlist_text', 'Schreib uns in deiner RSVP‑Nachricht deinen Lieblingssong für die Tanzfläche. Von 90s bis Disco ist alles willkommen.'),
('rsvp_deadline', '01.07.2026'),
('primary_color', '#f4d9df'),
('secondary_color', '#d5e4d7'),
('accent_color', '#9fb7cf'),
('text_color', '#302728'),
('heading_font', 'Great Vibes'),
('body_font', 'Nunito Sans'),
('hero_image', 'https://images.unsplash.com/photo-1519741497674-611481863552?auto=format&fit=crop&w=1800&q=80'),
('app_base_url', ''),
('frontend_enabled', '1'),
('syno_base_url', ''),
('syno_username', ''),
('syno_password', ''),
('syno_target_path', '/wedding-uploads'),
('syno_verify_ssl', '1'),
('gallery_master_key', ''),
('mail_from_name', 'Hochzeits-Team'),
('mail_from_address', 'no-reply@example.com'),
('mail_subject_template', 'Dein QR-Code für unsere Hochzeitsgalerie'),
('mail_body_template', 'Hallo {{guest_name}},\n\nwie schön, dass du dabei bist.\n\nDein persönlicher Galerie-Link:\n{{gallery_url}}\n\nDirekt zum Upload:\n{{upload_url}}\n\nQR-Code Bild:\n{{qr_image_url}}\n\nToken (manuell): {{token}}\n\nWir freuen uns auf dich!\n{{couple_names}}'),
('smtp_host', ''),
('smtp_port', '587'),
('smtp_encryption', 'tls'),
('smtp_username', ''),
('smtp_password', ''),
('smtp_timeout', '20')
ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value);

-- --------------------------------------------------------
-- Initial Admin User
-- 1) Generate password hash with PHP:
--    php -r "echo password_hash('ChangeMe123!', PASSWORD_DEFAULT), PHP_EOL;"
-- 2) Paste hash below and run insert.
-- --------------------------------------------------------
-- INSERT INTO users (username, email, password_hash, must_change_password, role)
-- VALUES ('admin', NULL, 'PASTE_PASSWORD_HASH_HERE', 1, 'admin')
-- ON DUPLICATE KEY UPDATE username = VALUES(username);
