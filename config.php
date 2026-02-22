<?php
declare(strict_types=1);

date_default_timezone_set('Europe/Berlin');

load_env_file(__DIR__ . '/.env');
bootstrap_session();
send_security_headers();

$autoloadPath = __DIR__ . '/vendor/autoload.php';
if (is_file($autoloadPath)) {
    require_once $autoloadPath;
}

const UPLOAD_MAX_BYTES = 15 * 1024 * 1024; // 15 MB per image

$CONFIG = [
    'db' => [
        'host' => getenv('DB_HOST') ?: '127.0.0.1',
        'name' => getenv('DB_NAME') ?: 'wedding_app',
        'user' => getenv('DB_USER') ?: 'root',
        'pass' => getenv('DB_PASS') ?: '',
    ],
    'app' => [
        'base_url' => rtrim((string) (getenv('APP_URL') ?: 'http://localhost/Hochzeit'), '/'),
    ],
    'paths' => [
        'uploads' => __DIR__ . '/uploads',
        'qrcodes' => __DIR__ . '/qrcodes',
    ],
    'synology' => [
        'base_url' => rtrim((string) (getenv('SYNO_BASE_URL') ?: ''), '/'),
        'username' => (string) (getenv('SYNO_USERNAME') ?: ''),
        'password' => (string) (getenv('SYNO_PASSWORD') ?: ''),
        'target_path' => (string) (getenv('SYNO_TARGET_PATH') ?: '/wedding-uploads'),
        'verify_ssl' => (getenv('SYNO_VERIFY_SSL') ?: '1') === '1',
    ],
];

ensure_storage_directories();
ensure_activity_logs_table();

function is_secure_request(): bool
{
    if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
        return true;
    }

    $proto = $_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '';
    if (is_string($proto) && strtolower(trim(explode(',', $proto)[0])) === 'https') {
        return true;
    }

    return false;
}

function bootstrap_session(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }

    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    ini_set('session.cookie_httponly', '1');

    $sameSiteRaw = trim((string) (getenv('SESSION_COOKIE_SAMESITE') ?: 'Lax'));
    $sameSite = ucfirst(strtolower($sameSiteRaw));
    if (!in_array($sameSite, ['Lax', 'Strict', 'None'], true)) {
        $sameSite = 'Lax';
    }

    $secureEnv = getenv('SESSION_COOKIE_SECURE');
    $secure = $secureEnv === false ? is_secure_request() : in_array(strtolower(trim((string) $secureEnv)), ['1', 'true', 'yes', 'on'], true);

    // session_set_cookie_params must happen before session_start.
    $cookieParams = session_get_cookie_params();
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => $cookieParams['path'] ?: '/',
        'domain' => $cookieParams['domain'] ?: '',
        'secure' => $secure,
        'httponly' => true,
        'samesite' => $sameSite,
    ]);

    session_start();
}

function send_security_headers(): void
{
    if (headers_sent()) {
        return;
    }

    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: SAMEORIGIN');
    header('Referrer-Policy: same-origin');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=()');

    // CSP is intentionally permissive for inline styles (theme variables) and Google Fonts.
    header(
        "Content-Security-Policy: "
        . "default-src 'self'; "
        . "base-uri 'self'; "
        . "form-action 'self'; "
        . "frame-ancestors 'self'; "
        . "img-src 'self' data: https:; "
        . "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        . "font-src 'self' data: https://fonts.gstatic.com; "
        . "script-src 'self'; "
        . "connect-src 'self' https:; "
        . "object-src 'none'"
    );

    if (is_secure_request()) {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    }
}

function load_env_file(string $path): void
{
    if (!is_file($path) || !is_readable($path)) {
        return;
    }

    $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if ($lines === false) {
        return;
    }

    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '' || str_starts_with($line, '#')) {
            continue;
        }

        if (str_starts_with($line, 'export ')) {
            $line = trim(substr($line, 7));
        }

        $separator = strpos($line, '=');
        if ($separator === false) {
            continue;
        }

        $name = trim(substr($line, 0, $separator));
        $value = trim(substr($line, $separator + 1));

        if ($name === '' || preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/', $name) !== 1) {
            continue;
        }

        if (getenv($name) !== false) {
            // Real environment variables have priority over values from .env.
            continue;
        }

        $firstChar = $value[0] ?? '';
        $isQuoted = ($firstChar === '"' || $firstChar === '\'') && str_ends_with($value, $firstChar);

        if ($isQuoted) {
            $value = substr($value, 1, -1);
        } else {
            $commentPos = strpos($value, ' #');
            if ($commentPos !== false) {
                $value = rtrim(substr($value, 0, $commentPos));
            }
        }

        putenv($name . '=' . $value);
        $_ENV[$name] = $value;
        $_SERVER[$name] = $value;
    }
}

function db(): PDO
{
    global $CONFIG;

    static $pdo = null;
    if ($pdo instanceof PDO) {
        return $pdo;
    }

    $dsn = sprintf(
        'mysql:host=%s;dbname=%s;charset=utf8mb4',
        $CONFIG['db']['host'],
        $CONFIG['db']['name']
    );

    $pdo = new PDO($dsn, $CONFIG['db']['user'], $CONFIG['db']['pass'], [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);

    return $pdo;
}

function app_base_url(): string
{
    global $CONFIG;

    static $resolved = null;
    if (is_string($resolved)) {
        return $resolved;
    }

    $baseUrl = $CONFIG['app']['base_url'];

    try {
        $stmt = db()->prepare('SELECT setting_value FROM settings WHERE setting_key = :key LIMIT 1');
        $stmt->execute([':key' => 'app_base_url']);
        $value = $stmt->fetchColumn();
        if (is_string($value) && trim($value) !== '') {
            $candidate = rtrim(trim($value), '/');
            if (filter_var($candidate, FILTER_VALIDATE_URL)) {
                $baseUrl = $candidate;
            }
        }
    } catch (Throwable) {
        // Fallback remains environment value.
    }

    $resolved = $baseUrl;

    return $resolved;
}

function synology_config(): array
{
    global $CONFIG;

    static $resolved = null;
    if (is_array($resolved)) {
        return $resolved;
    }

    $synology = $CONFIG['synology'];

    try {
        $stmt = db()->query(
            "SELECT setting_key, setting_value
             FROM settings
             WHERE setting_key IN (
                 'syno_base_url',
                 'syno_username',
                 'syno_password',
                 'syno_target_path',
                 'syno_verify_ssl'
             )"
        );
        $rows = $stmt->fetchAll();
        foreach ($rows as $row) {
            $key = (string) $row['setting_key'];
            $value = (string) $row['setting_value'];
            if ($key === 'syno_base_url' && $value !== '') {
                $synology['base_url'] = rtrim($value, '/');
            }
            if ($key === 'syno_username') {
                $synology['username'] = $value;
            }
            if ($key === 'syno_password') {
                $synology['password'] = $value;
            }
            if ($key === 'syno_target_path' && $value !== '') {
                $synology['target_path'] = $value;
            }
            if ($key === 'syno_verify_ssl') {
                $synology['verify_ssl'] = in_array(strtolower(trim($value)), ['1', 'true', 'yes', 'on'], true);
            }
        }
    } catch (Throwable) {
        // Fallback remains environment values.
    }

    $resolved = $synology;

    return $resolved;
}

function ensure_storage_directories(): void
{
    global $CONFIG;

    foreach ($CONFIG['paths'] as $path) {
        if (!is_dir($path)) {
            mkdir($path, 0775, true);
        }
    }
}

function redirect(string $url): void
{
    header('Location: ' . $url);
    exit;
}

function e(null|string|int|float $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function csrf_token(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }

    return (string) $_SESSION['csrf_token'];
}

function verify_csrf(?string $token): bool
{
    $sessionToken = (string) ($_SESSION['csrf_token'] ?? '');
    if ($sessionToken === '' || !is_string($token)) {
        return false;
    }

    return hash_equals($sessionToken, $token);
}

function random_token(int $bytes = 16): string
{
    return bin2hex(random_bytes($bytes));
}

function admin_sql_console_enabled(): bool
{
    return is_truthy_setting((string) (getenv('ADMIN_SQL_CONSOLE_ENABLED') ?: '0'));
}

function is_admin_logged_in(): bool
{
    return isset($_SESSION['admin_user_id']) && (int) $_SESSION['admin_user_id'] > 0;
}

function admin_login(int $userId, string $username, bool $forceSetup = false, ?string $email = null): void
{
    session_regenerate_id(true);
    $_SESSION['admin_user_id'] = $userId;
    $_SESSION['admin_username'] = $username;
    $_SESSION['admin_force_setup'] = $forceSetup ? 1 : 0;
    $_SESSION['admin_email'] = $email;
}

function admin_logout(): void
{
    unset(
        $_SESSION['admin_user_id'],
        $_SESSION['admin_username'],
        $_SESSION['admin_force_setup'],
        $_SESSION['admin_email']
    );
}

function admin_force_setup_required(): bool
{
    return (int) ($_SESSION['admin_force_setup'] ?? 0) === 1;
}

function admin_mark_setup_complete(string $email): void
{
    $_SESSION['admin_force_setup'] = 0;
    $_SESSION['admin_email'] = $email;
}

function get_all_settings(): array
{
    try {
        $stmt = db()->query('SELECT setting_key, setting_value FROM settings');
        $rows = $stmt->fetchAll();
    } catch (Throwable) {
        return [];
    }

    $settings = [];
    foreach ($rows as $row) {
        $settings[(string) $row['setting_key']] = (string) $row['setting_value'];
    }

    return $settings;
}

function get_setting(string $key, string $default = ''): string
{
    $settings = get_all_settings();

    return $settings[$key] ?? $default;
}

function is_truthy_setting(string $value): bool
{
    $value = strtolower(trim($value));

    return in_array($value, ['1', 'true', 'yes', 'on'], true);
}

function frontend_is_enabled(): bool
{
    return is_truthy_setting(get_setting('frontend_enabled', '1'));
}

function save_settings(array $settings): void
{
    $sql = 'INSERT INTO settings (setting_key, setting_value, updated_at)
            VALUES (:setting_key, :setting_value, NOW())
            ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value), updated_at = NOW()';
    $stmt = db()->prepare($sql);

    foreach ($settings as $key => $value) {
        $stmt->execute([
            ':setting_key' => (string) $key,
            ':setting_value' => (string) $value,
        ]);
    }
}

function ensure_activity_logs_table(): void
{
    static $initialized = false;
    if ($initialized) {
        return;
    }

    try {
        db()->exec(
            'CREATE TABLE IF NOT EXISTS activity_logs (
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
            ) ENGINE=InnoDB'
        );
    } catch (Throwable) {
        // Logging must never break the app runtime.
    }

    $initialized = true;
}

function client_ip_address(): string
{
    $candidates = [
        $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '',
        $_SERVER['HTTP_X_REAL_IP'] ?? '',
        $_SERVER['REMOTE_ADDR'] ?? '',
    ];

    foreach ($candidates as $candidate) {
        if (!is_string($candidate) || trim($candidate) === '') {
            continue;
        }

        $parts = explode(',', $candidate);
        foreach ($parts as $part) {
            $ip = trim($part);
            if ($ip !== '' && filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }
    }

    return '';
}

function request_user_agent(): string
{
    $agent = trim((string) ($_SERVER['HTTP_USER_AGENT'] ?? ''));
    if ($agent === '') {
        return '';
    }

    return substr($agent, 0, 255);
}

function log_event(string $eventType, string $message, array $context = []): void
{
    ensure_activity_logs_table();

    $eventType = substr(trim($eventType), 0, 80);
    $message = substr(trim($message), 0, 255);
    if ($eventType === '' || $message === '') {
        return;
    }

    $guestId = isset($context['guest_id']) ? (int) $context['guest_id'] : null;
    $tokenId = isset($context['token_id']) ? (int) $context['token_id'] : null;
    $userId = isset($context['user_id']) ? (int) $context['user_id'] : null;
    unset($context['guest_id'], $context['token_id'], $context['user_id']);

    $contextJson = null;
    if ($context !== []) {
        try {
            $encoded = json_encode($context, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
            $contextJson = is_string($encoded) ? $encoded : null;
        } catch (Throwable) {
            $contextJson = null;
        }
    }

    try {
        $stmt = db()->prepare(
            'INSERT INTO activity_logs
                (event_type, message, context_json, ip_address, user_agent, user_id, guest_id, token_id, created_at)
             VALUES
                (:event_type, :message, :context_json, :ip_address, :user_agent, :user_id, :guest_id, :token_id, NOW())'
        );
        $stmt->execute([
            ':event_type' => $eventType,
            ':message' => $message,
            ':context_json' => $contextJson,
            ':ip_address' => client_ip_address(),
            ':user_agent' => request_user_agent(),
            ':user_id' => $userId,
            ':guest_id' => $guestId,
            ':token_id' => $tokenId,
        ]);
    } catch (Throwable) {
        // Logging failures must not impact user features.
    }
}

function notification_defaults(): array
{
    return [
        'mail_from_name' => 'Hochzeits-Team',
        'mail_from_address' => 'no-reply@example.com',
        'mail_subject_template' => 'Dein QR-Code für unsere Hochzeitsgalerie',
        'mail_body_template' => "Hallo {{guest_name}},\n\nwie schön, dass du dabei bist.\n\nDein persönlicher Galerie-Link:\n{{gallery_url}}\n\nDirekt zum Upload:\n{{upload_url}}\n\nQR-Code Bild:\n{{qr_image_url}}\n\nToken (manuell): {{token}}\n\nWir freuen uns auf dich!\n{{couple_names}}",
        'gallery_master_key' => '',
    ];
}

function get_notification_settings(): array
{
    $defaults = notification_defaults();
    $settings = get_all_settings();

    return array_merge($defaults, array_intersect_key($settings, $defaults));
}

function smtp_defaults(): array
{
    return [
        'smtp_host' => '',
        'smtp_port' => '587',
        'smtp_encryption' => 'tls', // tls | ssl | none
        'smtp_username' => '',
        'smtp_password' => '',
        'smtp_timeout' => '20',
    ];
}

function get_smtp_settings(): array
{
    $defaults = smtp_defaults();
    $settings = get_all_settings();

    return array_merge($defaults, array_intersect_key($settings, $defaults));
}

function smtp_is_configured(?array $smtp = null): bool
{
    $smtp = is_array($smtp) ? $smtp : get_smtp_settings();

    return trim((string) ($smtp['smtp_host'] ?? '')) !== ''
        && (int) ($smtp['smtp_port'] ?? 0) > 0
        && trim((string) ($smtp['smtp_username'] ?? '')) !== ''
        && trim((string) ($smtp['smtp_password'] ?? '')) !== '';
}

function theme_defaults(): array
{
    return [
        'bride_name' => 'Lena',
        'groom_name' => 'Jonas',
        'hero_title' => 'Wir sagen Ja',
        'wedding_date' => '2026-08-15 14:30:00',
        'venue_name' => 'Gut Sonnenhof',
        'venue_address' => 'Sonnenweg 12, 50667 Köln',
        'intro_text' => 'Wir freuen uns auf einen unvergesslichen Tag mit euch voller Musik, Leichtigkeit und ganz viel Liebe.',
        'story_text_1' => 'Gestartet mit einem Espresso im Sommerregen, weitergegangen mit tausend kleinen Abenteuern. Zwischen Bahnsteigen, Sonntagsfrühstück und spontanen Roadtrips ist aus „wir schauen mal“ längst „für immer" geworden.',
        'story_text_2' => 'Am 15. August feiern wir diesen nächsten Schritt mit den Menschen, die uns am wichtigsten sind: euch.',
        'timeline_1_time' => '14:30',
        'timeline_1_title' => 'Freie Trauung',
        'timeline_1_text' => 'Im Rosengarten unter alten Linden. Taschentücher sind eingeplant.',
        'timeline_2_time' => '16:00',
        'timeline_2_title' => 'Empfang & Fotospots',
        'timeline_2_text' => 'Sekt, feine Häppchen und Zeit für gemeinsame Erinnerungsfotos.',
        'timeline_3_time' => '18:30',
        'timeline_3_title' => 'Dinner',
        'timeline_3_text' => 'Regional, saisonal und mit vegetarischen sowie veganen Optionen.',
        'timeline_4_time' => '21:00',
        'timeline_4_title' => 'Party',
        'timeline_4_text' => 'Eröffnungstanz, Live‑Band und danach DJ bis tief in die Nacht.',
        'travel_train_text' => 'Bis Köln Hbf, von dort Shuttle um 13:45 und 14:10 Uhr.',
        'travel_car_text' => 'Vor Ort stehen ausgeschilderte Parkplätze zur Verfügung.',
        'travel_nav_address' => 'Sonnenweg 12, 50667 Köln',
        'dresscode' => 'Summer Chic',
        'stays_intro' => 'Wir haben Zimmerkontingente bis zum 01.07.2026 reserviert:',
        'stay_option_1' => 'Hotel Gartenblick (8 Min.) – Stichwort „Lena & Jonas“',
        'stay_option_2' => 'Rhein Suites (12 Min.) – Shuttle um 01:00 und 02:00 Uhr',
        'stay_option_3' => 'Landhaus Bellevue (15 Min.) – ideal für Familien',
        'gift_text_1' => 'Eure Anwesenheit ist das größte Geschenk. Wenn ihr uns zusätzlich eine Freude machen möchtet, unterstützen wir gerne unseren Flitterwochen‑Fonds für Portugal.',
        'gift_text_2' => 'Vor Ort gibt es eine kleine Wunschbox für Karten und persönliche Nachrichten.',
        'playlist_text' => 'Schreib uns in deiner RSVP‑Nachricht deinen Lieblingssong für die Tanzfläche. Von 90s bis Disco ist alles willkommen.',
        'rsvp_deadline' => '01.07.2026',
        'primary_color' => '#f4d9df',
        'secondary_color' => '#d5e4d7',
        'accent_color' => '#9fb7cf',
        'text_color' => '#302728',
        'heading_font' => 'Great Vibes',
        'body_font' => 'Nunito Sans',
        'hero_image' => 'https://images.unsplash.com/photo-1519741497674-611481863552?auto=format&fit=crop&w=1800&q=80',
    ];
}

function get_theme_settings(): array
{
    return array_merge(theme_defaults(), get_all_settings());
}

function safe_color(string $value, string $fallback): string
{
    return preg_match('/^#[0-9a-fA-F]{3}(?:[0-9a-fA-F]{3})?$/', $value) ? $value : $fallback;
}

function safe_font_family(string $value, string $fallback): string
{
    return preg_match('/^[a-zA-Z0-9\s,\-\'\"]+$/', $value) ? $value : $fallback;
}

function render_theme_variables(array $theme): string
{
    $primary = safe_color((string) ($theme['primary_color'] ?? ''), '#f4d9df');
    $secondary = safe_color((string) ($theme['secondary_color'] ?? ''), '#d5e4d7');
    $accent = safe_color((string) ($theme['accent_color'] ?? ''), '#9fb7cf');
    $text = safe_color((string) ($theme['text_color'] ?? ''), '#302728');
    $headingFont = safe_font_family((string) ($theme['heading_font'] ?? ''), 'Great Vibes');
    $bodyFont = safe_font_family((string) ($theme['body_font'] ?? ''), 'Nunito Sans');

    return sprintf(
        ':root{--primary:%s;--secondary:%s;--accent:%s;--text:%s;--display-font:"%s",cursive;--body-font:"%s",sans-serif;}',
        e($primary),
        e($secondary),
        e($accent),
        e($text),
        e($headingFont),
        e($bodyFont)
    );
}

function format_wedding_datetime(string $value): string
{
    try {
        $date = new DateTimeImmutable($value);
    } catch (Throwable) {
        return $value;
    }

    return $date->format('d.m.Y · H:i') . ' Uhr';
}

function gallery_url_for_token(string $token): string
{
    return app_base_url() . '/gallery.php?token=' . urlencode($token);
}

function generate_gallery_master_key(int $length = 32): string
{
    $length = max(16, $length);
    $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{}';
    $maxIndex = strlen($chars) - 1;

    do {
        $key = '';
        for ($index = 0; $index < $length; $index++) {
            $key .= $chars[random_int(0, $maxIndex)];
        }
    } while (
        preg_match('/[A-Z]/', $key) !== 1
        || preg_match('/[a-z]/', $key) !== 1
        || preg_match('/[0-9]/', $key) !== 1
        || preg_match('/[^A-Za-z0-9]/', $key) !== 1
    );

    return $key;
}

function is_strong_gallery_master_key(string $key): bool
{
    if (strlen($key) !== 32) {
        return false;
    }

    return preg_match('/[A-Z]/', $key) === 1
        && preg_match('/[a-z]/', $key) === 1
        && preg_match('/[0-9]/', $key) === 1
        && preg_match('/[^A-Za-z0-9]/', $key) === 1;
}

function gallery_master_key(): string
{
    static $resolved = null;
    if (is_string($resolved)) {
        return $resolved;
    }

    $settings = get_all_settings();
    $candidate = trim((string) ($settings['gallery_master_key'] ?? ''));

    if (!is_strong_gallery_master_key($candidate)) {
        $fallback = trim((string) (getenv('GALLERY_MASTER_KEY') ?: ''));
        if (is_strong_gallery_master_key($fallback)) {
            $candidate = $fallback;
        } else {
            $candidate = generate_gallery_master_key(32);
        }

        try {
            save_settings(['gallery_master_key' => $candidate]);
        } catch (Throwable) {
            // Ignore persistence failure and still return generated key.
        }
    }

    $resolved = $candidate;

    return $resolved;
}

function is_gallery_master_key(string $candidate): bool
{
    $candidate = trim($candidate);
    if ($candidate === '') {
        return false;
    }

    $masterKey = gallery_master_key();
    if ($masterKey === '') {
        return false;
    }

    return hash_equals($masterKey, $candidate);
}

function set_gallery_master_access(): void
{
    session_regenerate_id(true);
    $_SESSION['gallery_master_access'] = 1;
    unset($_SESSION['gallery_access']);
}

function has_gallery_master_access(): bool
{
    return (int) ($_SESSION['gallery_master_access'] ?? 0) === 1;
}

function validate_gallery_token(string $token): ?array
{
    if (!preg_match('/^[a-f0-9]{16,128}$/i', $token)) {
        return null;
    }

    $sql = 'SELECT qt.id, qt.guest_id, qt.token, qt.expires_at, qt.is_active, qt.qr_path,
                   g.first_name, g.last_name
            FROM qr_tokens qt
            JOIN guests g ON g.id = qt.guest_id
            WHERE qt.token = :token
              AND qt.is_active = 1
              AND (qt.expires_at IS NULL OR qt.expires_at > NOW())
            LIMIT 1';

    $stmt = db()->prepare($sql);
    $stmt->execute([':token' => $token]);
    $row = $stmt->fetch();

    if (!$row) {
        return null;
    }

    return $row;
}

function set_gallery_access(array $tokenRow): void
{
    session_regenerate_id(true);
    $_SESSION['gallery_access'] = [
        'token' => (string) $tokenRow['token'],
        'token_id' => (int) $tokenRow['id'],
        'guest_id' => (int) $tokenRow['guest_id'],
        'guest_name' => trim((string) $tokenRow['first_name'] . ' ' . (string) $tokenRow['last_name']),
    ];
    unset($_SESSION['gallery_master_access']);
}

function get_gallery_access(): ?array
{
    $savedToken = $_SESSION['gallery_access']['token'] ?? null;
    if (!is_string($savedToken) || $savedToken === '') {
        return null;
    }

    $validated = validate_gallery_token($savedToken);
    if (!$validated) {
        unset($_SESSION['gallery_access']);
        return null;
    }

    $context = [
        'token' => (string) $validated['token'],
        'token_id' => (int) $validated['id'],
        'guest_id' => (int) $validated['guest_id'],
        'guest_name' => trim((string) $validated['first_name'] . ' ' . (string) $validated['last_name']),
    ];

    $_SESSION['gallery_access'] = $context;

    return $context;
}

function clear_gallery_access(): void
{
    unset($_SESSION['gallery_access'], $_SESSION['gallery_master_access']);
}

function require_gallery_access(): array
{
    $context = get_gallery_access();
    if ($context === null) {
        redirect('gallery.php');
    }

    return $context;
}

function master_upload_display_name(): string
{
    $theme = get_theme_settings();
    $a = trim((string) ($theme['bride_name'] ?? ''));
    $b = trim((string) ($theme['groom_name'] ?? ''));

    $parts = array_values(array_filter([$a, $b], static fn(string $value): bool => $value !== ''));
    $label = trim(implode(' ', $parts));

    return $label !== '' ? $label : 'Brautpaar';
}

function require_gallery_upload_access(): array
{
    $context = get_gallery_access();
    if ($context !== null) {
        $context['is_master'] = false;
        return $context;
    }

    if (has_gallery_master_access()) {
        return [
            'token' => 'master',
            'token_id' => 0,
            'guest_id' => 0,
            'guest_name' => master_upload_display_name(),
            'is_master' => true,
        ];
    }

    redirect('gallery.php');
}

function interpolate_template(string $template, array $variables): string
{
    $replace = [];
    foreach ($variables as $key => $value) {
        $replace['{{' . $key . '}}'] = (string) $value;
    }

    return strtr($template, $replace);
}

function sanitize_mail_header(string $value): string
{
    return trim(str_replace(["\r", "\n"], '', $value));
}

function smtp_encode_header(string $value): string
{
    $value = sanitize_mail_header($value);
    if ($value === '') {
        return '';
    }

    if (function_exists('mb_encode_mimeheader')) {
        return (string) mb_encode_mimeheader($value, 'UTF-8', 'B', "\r\n");
    }

    return $value;
}

function smtp_read_response($socket): array
{
    $lines = [];
    $code = 0;

    while (!feof($socket)) {
        $line = fgets($socket, 1024);
        if ($line === false) {
            break;
        }
        $line = rtrim($line, "\r\n");
        $lines[] = $line;
        if (preg_match('/^(\d{3})([ -])/', $line, $matches) === 1) {
            $code = (int) $matches[1];
            if (($matches[2] ?? '') === ' ') {
                break;
            }
        }
    }

    return [
        'code' => $code,
        'text' => implode("\n", $lines),
    ];
}

function smtp_expect($socket, array $allowedCodes): array
{
    $response = smtp_read_response($socket);
    if (!in_array((int) $response['code'], $allowedCodes, true)) {
        throw new RuntimeException('SMTP-Fehler: ' . ($response['text'] !== '' ? $response['text'] : 'Keine Antwort vom Server.'));
    }

    return $response;
}

function smtp_write($socket, string $command): void
{
    $bytes = fwrite($socket, $command . "\r\n");
    if ($bytes === false) {
        throw new RuntimeException('SMTP-Kommando konnte nicht gesendet werden.');
    }
}

function smtp_send_mail(
    string $toAddress,
    string $subject,
    string $htmlBody,
    string $plainBody,
    string $fromName,
    string $fromAddress,
    ?array $smtp = null
): array {
    $smtp = is_array($smtp) ? $smtp : get_smtp_settings();
    if (!smtp_is_configured($smtp)) {
        return ['success' => false, 'message' => 'SMTP ist nicht konfiguriert.'];
    }
    if (!filter_var($toAddress, FILTER_VALIDATE_EMAIL)) {
        return ['success' => false, 'message' => 'Ungültige Empfänger-E-Mail.'];
    }
    if (!filter_var($fromAddress, FILTER_VALIDATE_EMAIL)) {
        return ['success' => false, 'message' => 'Ungültige SMTP-Absender-E-Mail.'];
    }

    $host = trim((string) ($smtp['smtp_host'] ?? ''));
    $port = (int) ($smtp['smtp_port'] ?? 587);
    $encryption = strtolower(trim((string) ($smtp['smtp_encryption'] ?? 'tls')));
    $username = (string) ($smtp['smtp_username'] ?? '');
    $password = (string) ($smtp['smtp_password'] ?? '');
    $timeout = max(5, (int) ($smtp['smtp_timeout'] ?? 20));

    if (!in_array($encryption, ['tls', 'ssl', 'none'], true)) {
        $encryption = 'tls';
    }
    if ($port <= 0) {
        $port = $encryption === 'ssl' ? 465 : 587;
    }

    $remoteHost = ($encryption === 'ssl' ? 'ssl://' : '') . $host;
    $socket = @stream_socket_client($remoteHost . ':' . $port, $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT);
    if (!is_resource($socket)) {
        return ['success' => false, 'message' => 'SMTP-Verbindung fehlgeschlagen: ' . $errstr . ' (' . $errno . ')'];
    }

    stream_set_timeout($socket, $timeout);
    $helloHost = parse_url(app_base_url(), PHP_URL_HOST);
    if (!is_string($helloHost) || $helloHost === '') {
        $helloHost = 'localhost';
    }

    try {
        smtp_expect($socket, [220]);
        smtp_write($socket, 'EHLO ' . $helloHost);
        smtp_expect($socket, [250]);

        if ($encryption === 'tls') {
            smtp_write($socket, 'STARTTLS');
            smtp_expect($socket, [220]);

            $cryptoEnabled = stream_socket_enable_crypto($socket, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
            if ($cryptoEnabled !== true) {
                throw new RuntimeException('SMTP STARTTLS konnte nicht aktiviert werden.');
            }

            smtp_write($socket, 'EHLO ' . $helloHost);
            smtp_expect($socket, [250]);
        }

        smtp_write($socket, 'AUTH LOGIN');
        smtp_expect($socket, [334]);
        smtp_write($socket, base64_encode($username));
        smtp_expect($socket, [334]);
        smtp_write($socket, base64_encode($password));
        smtp_expect($socket, [235]);

        smtp_write($socket, 'MAIL FROM:<' . $fromAddress . '>');
        smtp_expect($socket, [250]);
        smtp_write($socket, 'RCPT TO:<' . $toAddress . '>');
        smtp_expect($socket, [250, 251]);
        smtp_write($socket, 'DATA');
        smtp_expect($socket, [354]);

        $boundary = 'bnd_' . bin2hex(random_bytes(8));
        $subjectHeader = smtp_encode_header($subject);
        $fromHeader = smtp_encode_header($fromName) . ' <' . $fromAddress . '>';
        $plainBody = str_replace(["\r\n", "\r"], "\n", $plainBody);
        $htmlBody = str_replace(["\r\n", "\r"], "\n", $htmlBody);

        $headers = [
            'Date: ' . gmdate('D, d M Y H:i:s') . ' +0000',
            'From: ' . $fromHeader,
            'To: <' . $toAddress . '>',
            'Subject: ' . $subjectHeader,
            'MIME-Version: 1.0',
            'Content-Type: multipart/alternative; boundary="' . $boundary . '"',
        ];

        $bodyLines = [
            '--' . $boundary,
            'Content-Type: text/plain; charset=UTF-8',
            'Content-Transfer-Encoding: 8bit',
            '',
            $plainBody,
            '--' . $boundary,
            'Content-Type: text/html; charset=UTF-8',
            'Content-Transfer-Encoding: 8bit',
            '',
            $htmlBody,
            '--' . $boundary . '--',
        ];

        $data = implode("\r\n", array_merge($headers, [''], $bodyLines));
        $data = preg_replace('/(?m)^\./', '..', $data);
        if (!is_string($data)) {
            throw new RuntimeException('SMTP-Daten konnten nicht vorbereitet werden.');
        }

        $written = fwrite($socket, $data . "\r\n.\r\n");
        if ($written === false) {
            throw new RuntimeException('SMTP-Daten konnten nicht gesendet werden.');
        }
        smtp_expect($socket, [250]);

        smtp_write($socket, 'QUIT');
        smtp_expect($socket, [221, 250]);
    } catch (Throwable $exception) {
        fclose($socket);
        return ['success' => false, 'message' => $exception->getMessage()];
    }

    fclose($socket);

    return ['success' => true, 'message' => 'SMTP-Mail erfolgreich versendet.'];
}

function send_guest_qr_email(array $guest, array $tokenData): array
{
    $email = strtolower(trim((string) ($guest['email'] ?? '')));
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return ['success' => false, 'message' => 'Keine gültige E-Mail-Adresse beim Gast hinterlegt.'];
    }

    $settings = get_notification_settings();
    $theme = get_theme_settings();
    $guestName = trim((string) ($guest['first_name'] ?? '') . ' ' . (string) ($guest['last_name'] ?? ''));
    if ($guestName === '') {
        $guestName = 'lieber Gast';
    }

    $token = (string) ($tokenData['token'] ?? '');
    $galleryUrl = (string) ($tokenData['url'] ?? '');
    $qrPath = ltrim((string) ($tokenData['qr_path'] ?? ''), '/');
    $qrImageUrl = $qrPath !== '' ? app_base_url() . '/' . $qrPath : '';
    $uploadUrl = app_base_url() . '/upload.php';
    $coupleNames = trim((string) ($theme['bride_name'] ?? '') . ' & ' . (string) ($theme['groom_name'] ?? ''));
    if ($coupleNames === '&' || $coupleNames === '') {
        $coupleNames = 'wir beide';
    }

    $variables = [
        'guest_name' => $guestName,
        'gallery_url' => $galleryUrl,
        'upload_url' => $uploadUrl,
        'qr_image_url' => $qrImageUrl,
        'token' => $token,
        'couple_names' => $coupleNames,
    ];

    $subjectTemplate = (string) ($settings['mail_subject_template'] ?? notification_defaults()['mail_subject_template']);
    $bodyTemplate = (string) ($settings['mail_body_template'] ?? notification_defaults()['mail_body_template']);
    $subject = interpolate_template($subjectTemplate, $variables);
    $plainBody = interpolate_template($bodyTemplate, $variables);

    $htmlBody = '<html><body style="font-family:Arial,sans-serif;color:#2f2f2f;line-height:1.55;">'
        . nl2br(e($plainBody))
        . ($qrImageUrl !== '' ? '<p><a href="' . e($qrImageUrl) . '">QR-Code öffnen</a></p>' : '')
        . '</body></html>';

    $fromName = sanitize_mail_header((string) ($settings['mail_from_name'] ?? 'Hochzeits-Team'));
    $fromAddress = strtolower(trim((string) ($settings['mail_from_address'] ?? '')));

    return smtp_send_mail(
        $email,
        $subject,
        $htmlBody,
        $plainBody,
        $fromName,
        $fromAddress,
        get_smtp_settings()
    );
}

function load_qr_library(): void
{
    if (class_exists('QRcode')) {
        return;
    }

    $candidateFiles = [
        __DIR__ . '/vendor/phpqrcode/qrlib.php',
        __DIR__ . '/vendor/phpqrcode/phpqrcode/qrlib.php',
        __DIR__ . '/vendor/chillerlan/php-qrcode/src/QRCode.php',
    ];

    foreach ($candidateFiles as $file) {
        if (is_file($file)) {
            require_once $file;
            if (
                class_exists('QRcode')
                || (class_exists('chillerlan\\QRCode\\QRCode') && class_exists('chillerlan\\QRCode\\QROptions'))
            ) {
                return;
            }
        }
    }

    if (class_exists('chillerlan\\QRCode\\QRCode') && class_exists('chillerlan\\QRCode\\QROptions')) {
        return;
    }

    throw new RuntimeException('QR-Bibliothek nicht gefunden. Bitte installiere sie via Composer (z. B. composer require chillerlan/php-qrcode oder phpqrcode/phpqrcode).');
}

function with_file_extension(string $path, string $extension): string
{
    $normalizedExtension = ltrim($extension, '.');
    if ($normalizedExtension === '') {
        return $path;
    }

    $trimmedPath = preg_replace('/\.[^.\/]+$/', '', $path);
    if (!is_string($trimmedPath) || $trimmedPath === '') {
        $trimmedPath = $path;
    }

    return $trimmedPath . '.' . $normalizedExtension;
}

function generate_qr_code_image(string $content, string $relativePath): string
{
    load_qr_library();

    $relativePath = ltrim($relativePath, '/');
    $absolutePath = __DIR__ . '/' . $relativePath;
    $directory = dirname($absolutePath);
    if (!is_dir($directory)) {
        mkdir($directory, 0775, true);
    }

    if (class_exists('QRcode') && extension_loaded('gd')) {
        QRcode::png($content, $absolutePath, QR_ECLEVEL_M, 7, 2);
        return $relativePath;
    }

    if (class_exists('chillerlan\\QRCode\\QRCode')) {
        $outputType = extension_loaded('gd')
            ? chillerlan\QRCode\QRCode::OUTPUT_IMAGE_PNG
            : chillerlan\QRCode\QRCode::OUTPUT_MARKUP_SVG;
        $relativePath = with_file_extension($relativePath, $outputType === chillerlan\QRCode\QRCode::OUTPUT_IMAGE_PNG ? 'png' : 'svg');
        $absolutePath = __DIR__ . '/' . $relativePath;

        $options = new chillerlan\QRCode\QROptions([
            'outputType' => $outputType,
            'eccLevel' => chillerlan\QRCode\QRCode::ECC_M,
            'scale' => 7,
        ]);

        if ($outputType === chillerlan\QRCode\QRCode::OUTPUT_IMAGE_PNG) {
            (new chillerlan\QRCode\QRCode($options))->render($content, $absolutePath);
            return $relativePath;
        }

        $svgMarkup = (new chillerlan\QRCode\QRCode($options))->render($content);
        if (!is_string($svgMarkup) || trim($svgMarkup) === '') {
            throw new RuntimeException('QR-Code (SVG) konnte nicht generiert werden.');
        }
        if (file_put_contents($absolutePath, $svgMarkup) === false) {
            throw new RuntimeException('QR-Code (SVG) konnte nicht gespeichert werden.');
        }

        return $relativePath;
    }

    if (!extension_loaded('gd')) {
        throw new RuntimeException('ext-gd not loaded. Installiere php-gd oder nutze chillerlan/php-qrcode (SVG-Fallback).');
    }

    throw new RuntimeException('Keine kompatible QR-Implementierung geladen.');
}

function create_guest_qr_token(int $guestId, ?string $expiresAt = null): array
{
    $pdo = db();
    $token = random_token(16);
    $pdo->beginTransaction();

    try {
        $insert = $pdo->prepare(
            'INSERT INTO qr_tokens (guest_id, token, expires_at, is_active, created_at)
             VALUES (:guest_id, :token, :expires_at, 1, NOW())'
        );
        $insert->execute([
            ':guest_id' => $guestId,
            ':token' => $token,
            ':expires_at' => $expiresAt,
        ]);

        $tokenId = (int) $pdo->lastInsertId();
        $qrPath = generate_qr_code_image(gallery_url_for_token($token), 'qrcodes/token_' . $tokenId . '.png');

        $update = $pdo->prepare('UPDATE qr_tokens SET qr_path = :qr_path WHERE id = :id');
        $update->execute([
            ':qr_path' => $qrPath,
            ':id' => $tokenId,
        ]);

        $pdo->commit();

        return [
            'id' => $tokenId,
            'token' => $token,
            'qr_path' => $qrPath,
            'url' => gallery_url_for_token($token),
        ];
    } catch (Throwable $exception) {
        $pdo->rollBack();
        throw $exception;
    }
}

function sanitize_path_segment(string $value, string $fallback = 'gast'): string
{
    $value = trim($value);
    if ($value === '') {
        return $fallback;
    }

    if (function_exists('iconv')) {
        $converted = iconv('UTF-8', 'ASCII//TRANSLIT//IGNORE', $value);
        if (is_string($converted) && $converted !== '') {
            $value = $converted;
        }
    }

    $value = strtolower($value);
    $value = preg_replace('/[^a-z0-9]+/', '-', $value);
    if (!is_string($value)) {
        return $fallback;
    }

    $value = trim($value, '-');
    if ($value === '') {
        return $fallback;
    }

    return $value;
}

function synology_guest_folder_path(int $guestId, string $guestName): string
{
    unset($guestId);
    $config = synology_config();
    $basePath = trim((string) ($config['target_path'] ?? ''));
    if ($basePath === '') {
        $basePath = '/wedding-uploads';
    }

    $basePath = '/' . trim($basePath, '/');
    $folderName = trim($guestName);
    $folderName = preg_replace('/[\/\\\\:\*\?"<>\|]+/', '', $folderName);
    if (!is_string($folderName)) {
        $folderName = '';
    }
    $folderName = preg_replace('/\s+/', ' ', $folderName);
    if (!is_string($folderName) || trim($folderName) === '') {
        $folderName = 'Gast';
    }

    return $basePath . '/' . trim($folderName);
}

function is_synology_configured(): bool
{
    $config = synology_config();

    $baseUrl = strtolower(trim((string) $config['base_url']));
    $username = strtolower(trim((string) $config['username']));
    $password = trim((string) $config['password']);
    $targetPath = trim((string) $config['target_path']);

    if (
        str_contains($baseUrl, 'deine-nas')
        || str_contains($baseUrl, 'example.com')
        || $username === 'dein-benutzer'
        || $password === 'dein-passwort'
    ) {
        return false;
    }

    return $config['base_url'] !== ''
        && $config['username'] !== ''
        && $config['password'] !== ''
        && $targetPath !== '';
}

function synology_error_message(array $response): string
{
    if (($response['success'] ?? false) === true) {
        return '';
    }

    $code = $response['error']['code'] ?? null;
    if ($code === null) {
        return 'Unbekannter Synology-Fehler.';
    }

    return 'Synology-Fehlercode: ' . $code;
}

function curl_json_request(string $url, ?array $postFields = null): array
{
    $synology = synology_config();

    if (!function_exists('curl_init')) {
        throw new RuntimeException('Die cURL-Erweiterung ist nicht aktiviert.');
    }

    $ch = curl_init($url);
    if ($ch === false) {
        throw new RuntimeException('cURL konnte nicht initialisiert werden.');
    }

    $options = [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_TIMEOUT => 60,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_SSL_VERIFYPEER => (bool) $synology['verify_ssl'],
        CURLOPT_SSL_VERIFYHOST => (bool) $synology['verify_ssl'] ? 2 : 0,
    ];

    if ($postFields !== null) {
        $options[CURLOPT_POST] = true;
        $options[CURLOPT_POSTFIELDS] = $postFields;
    }

    curl_setopt_array($ch, $options);

    $raw = curl_exec($ch);
    if ($raw === false) {
        $error = curl_error($ch);
        curl_close($ch);
        throw new RuntimeException('Synology cURL-Fehler: ' . $error);
    }

    $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    $decoded = json_decode($raw, true);
    if (!is_array($decoded)) {
        throw new RuntimeException('Ungültige Synology-Antwort (HTTP ' . $status . ').');
    }

    return $decoded;
}

function upload_to_synology(string $localFile, string $targetFilename, ?string $targetPath = null): ?string
{
    $config = synology_config();
    if (!is_synology_configured()) {
        return null;
    }

    $baseUrl = rtrim((string) $config['base_url'], '/');
    $loginUrl = $baseUrl
        . '/webapi/auth.cgi?api=SYNO.API.Auth&version=6&method=login'
        . '&account=' . rawurlencode((string) $config['username'])
        . '&passwd=' . rawurlencode((string) $config['password'])
        . '&session=FileStation&format=sid';

    $loginResponse = curl_json_request($loginUrl);
    if (($loginResponse['success'] ?? false) !== true) {
        throw new RuntimeException('Synology Login fehlgeschlagen. ' . synology_error_message($loginResponse));
    }

    $sid = $loginResponse['data']['sid'] ?? null;
    if (!is_string($sid) || $sid === '') {
        throw new RuntimeException('Synology SID fehlt in der Antwort.');
    }

    try {
        $uploadUrl = $baseUrl . '/webapi/entry.cgi?api=SYNO.FileStation.Upload&version=2&method=upload&_sid=' . rawurlencode($sid);
        $mime = mime_content_type($localFile) ?: 'application/octet-stream';
        $resolvedTargetPath = trim((string) ($targetPath ?? ''));
        if ($resolvedTargetPath === '') {
            $resolvedTargetPath = (string) $config['target_path'];
        }

        $payload = [
            'path' => $resolvedTargetPath,
            'create_parents' => 'true',
            'overwrite' => 'false',
            'file' => new CURLFile($localFile, $mime, $targetFilename),
        ];

        $uploadResponse = curl_json_request($uploadUrl, $payload);
        if (($uploadResponse['success'] ?? false) !== true) {
            throw new RuntimeException('Synology Upload fehlgeschlagen. ' . synology_error_message($uploadResponse));
        }

        return rtrim($resolvedTargetPath, '/') . '/' . $targetFilename;
    } finally {
        $logoutUrl = $baseUrl
            . '/webapi/auth.cgi?api=SYNO.API.Auth&version=2&method=logout'
            . '&session=FileStation&_sid=' . rawurlencode($sid);

        try {
            curl_json_request($logoutUrl);
        } catch (Throwable) {
            // Logout-Fehler sollen den Uploadfluss nicht unterbrechen.
        }
    }
}

function normalize_uploaded_files(array $fileInput): array
{
    if (!isset($fileInput['name'])) {
        return [];
    }

    if (!is_array($fileInput['name'])) {
        return [$fileInput];
    }

    $normalized = [];
    $count = count($fileInput['name']);

    for ($index = 0; $index < $count; $index++) {
        $normalized[] = [
            'name' => $fileInput['name'][$index] ?? '',
            'type' => $fileInput['type'][$index] ?? '',
            'tmp_name' => $fileInput['tmp_name'][$index] ?? '',
            'error' => $fileInput['error'][$index] ?? UPLOAD_ERR_NO_FILE,
            'size' => $fileInput['size'][$index] ?? 0,
        ];
    }

    return $normalized;
}

function allowed_image_mime_types(): array
{
    return [
        'image/jpeg' => 'jpg',
        'image/png' => 'png',
        'image/webp' => 'webp',
    ];
}

function upload_error_message(int $error): string
{
    return match ($error) {
        UPLOAD_ERR_OK => 'OK',
        UPLOAD_ERR_INI_SIZE, UPLOAD_ERR_FORM_SIZE => 'Datei zu groß.',
        UPLOAD_ERR_PARTIAL => 'Upload war unvollständig.',
        UPLOAD_ERR_NO_FILE => 'Keine Datei ausgewählt.',
        UPLOAD_ERR_NO_TMP_DIR => 'Temporäres Verzeichnis fehlt.',
        UPLOAD_ERR_CANT_WRITE => 'Datei konnte nicht geschrieben werden.',
        UPLOAD_ERR_EXTENSION => 'Upload durch Erweiterung gestoppt.',
        default => 'Unbekannter Upload-Fehler.',
    };
}
