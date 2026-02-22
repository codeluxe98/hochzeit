<?php
declare(strict_types=1);

require_once __DIR__ . '/config.php';

function ensure_admin_user_schema(): void
{
    $pdo = db();
    $tableExists = (int) $pdo->query(
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'users'"
    )->fetchColumn();

    if ($tableExists === 0) {
        return;
    }

    $columns = $pdo->query(
        "SELECT COLUMN_NAME FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = 'users'"
    )->fetchAll(PDO::FETCH_COLUMN);

    if (!in_array('email', $columns, true)) {
        $pdo->exec('ALTER TABLE users ADD COLUMN email VARCHAR(190) DEFAULT NULL AFTER username');
    }

    if (!in_array('must_change_password', $columns, true)) {
        $pdo->exec('ALTER TABLE users ADD COLUMN must_change_password TINYINT(1) NOT NULL DEFAULT 1 AFTER password_hash');
    }

    if (!in_array('updated_at', $columns, true)) {
        $pdo->exec('ALTER TABLE users ADD COLUMN updated_at TIMESTAMP NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP AFTER created_at');
    }

    $indexExists = (int) $pdo->query(
        "SELECT COUNT(*) FROM information_schema.statistics WHERE table_schema = DATABASE() AND table_name = 'users' AND index_name = 'uq_users_email'"
    )->fetchColumn();

    if ($indexExists === 0) {
        $pdo->exec('ALTER TABLE users ADD UNIQUE KEY uq_users_email (email)');
    }

    $pdo->exec("UPDATE users SET email = NULL WHERE TRIM(COALESCE(email, '')) = ''");
    $pdo->exec('UPDATE users SET must_change_password = 1 WHERE email IS NULL');
}

function ensure_default_admin_user(): ?array
{
    $pdo = db();
    $tableExists = (int) $pdo->query(
        "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'users'"
    )->fetchColumn();

    if ($tableExists === 0) {
        return null;
    }

    $userCount = (int) $pdo->query('SELECT COUNT(*) FROM users')->fetchColumn();
    if ($userCount > 0) {
        return null;
    }

    $username = trim((string) (getenv('ADMIN_INITIAL_USERNAME') ?: 'admin'));
    if ($username === '') {
        $username = 'admin';
    }

    $initialPassword = trim((string) (getenv('ADMIN_INITIAL_PASSWORD') ?: ''));
    if ($initialPassword === '') {
        throw new RuntimeException('ADMIN_INITIAL_PASSWORD ist nicht gesetzt. Setze ein starkes Startpasswort, damit der initiale Admin erstellt werden kann.');
    }

    if (strlen($initialPassword) < 12) {
        throw new RuntimeException('ADMIN_INITIAL_PASSWORD muss mindestens 12 Zeichen lang sein.');
    }
    $passwordHash = password_hash($initialPassword, PASSWORD_DEFAULT);
    if (!is_string($passwordHash)) {
        throw new RuntimeException('Initiales Admin-Passwort konnte nicht gehasht werden.');
    }

    $stmt = $pdo->prepare(
        'INSERT INTO users (username, email, password_hash, must_change_password, role, created_at, updated_at)
         VALUES (:username, NULL, :password_hash, 1, \'admin\', NOW(), NOW())'
    );
    $stmt->execute([
        ':username' => $username,
        ':password_hash' => $passwordHash,
    ]);

    return [
        'username' => $username,
        'password' => $initialPassword,
    ];
}

function get_current_admin_user(): ?array
{
    if (!is_admin_logged_in()) {
        return null;
    }

    $stmt = db()->prepare(
        'SELECT id, username, email, must_change_password
         FROM users
         WHERE id = :id
         LIMIT 1'
    );
    $stmt->execute([':id' => (int) ($_SESSION['admin_user_id'] ?? 0)]);
    $user = $stmt->fetch();

    return $user ?: null;
}

function admin_user_requires_first_login_setup(?array $user): bool
{
    if ($user === null) {
        return true;
    }

    $email = trim((string) ($user['email'] ?? ''));

    return (int) ($user['must_change_password'] ?? 1) === 1 || $email === '';
}

function admin_manageable_tables(): array
{
    return ['users', 'guests', 'qr_tokens', 'photos', 'settings', 'activity_logs'];
}

function admin_valid_identifier(string $identifier): bool
{
    return preg_match('/^[a-zA-Z0-9_]+$/', $identifier) === 1;
}

function admin_fetch_table_columns(string $table): array
{
    if (!admin_valid_identifier($table)) {
        return [];
    }

    $stmt = db()->prepare(
        "SELECT COLUMN_NAME, DATA_TYPE, COLUMN_KEY, IS_NULLABLE, EXTRA
         FROM information_schema.columns
         WHERE table_schema = DATABASE()
           AND table_name = :table_name
         ORDER BY ORDINAL_POSITION"
    );
    $stmt->execute([':table_name' => $table]);

    return $stmt->fetchAll();
}

$theme = get_theme_settings();
$errors = [];
$success = [];
$defaultAdminCredentials = null;
$sqlConsoleOutput = '';
$sqlConsoleRows = [];
$sqlConsoleColumns = [];
$dbPreviewTable = 'settings';
$dbPreviewRows = [];
$dbPreviewColumns = [];
$recentLogs = [];
$activeTab = 'tab-guests';

try {
    ensure_admin_user_schema();
    $defaultAdminCredentials = ensure_default_admin_user();
} catch (Throwable $exception) {
    $errors[] = 'Admin-Benutzer konnte nicht vorbereitet werden: ' . $exception->getMessage();
}

if (isset($_GET['logout']) && $_GET['logout'] === '1') {
    log_event('admin_logout', 'Admin hat sich abgemeldet', [
        'user_id' => (int) ($_SESSION['admin_user_id'] ?? 0),
    ]);
    admin_logout();
    redirect('admin.php');
}

if (isset($_GET['setup']) && $_GET['setup'] === 'done') {
    $success[] = 'Profil erfolgreich aktualisiert. Willkommen im Admin-Panel.';
}

if (!is_admin_logged_in() && $_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'login') {
    if (!verify_csrf($_POST['csrf_token'] ?? null)) {
        $errors[] = 'Sicherheitsprüfung fehlgeschlagen.';
        log_event('admin_login_error', 'Admin-Login mit ungültigem CSRF-Token');
    } else {
        $username = trim((string) ($_POST['username'] ?? ''));
        $password = (string) ($_POST['password'] ?? '');

        try {
            $stmt = db()->prepare(
                'SELECT id, username, email, password_hash, must_change_password
                 FROM users
                 WHERE username = :username
                 LIMIT 1'
            );
            $stmt->execute([':username' => $username]);
            $user = $stmt->fetch();

            if ($user && password_verify($password, (string) $user['password_hash'])) {
                $mustSetup = admin_user_requires_first_login_setup($user);
                admin_login((int) $user['id'], (string) $user['username'], $mustSetup, (string) ($user['email'] ?? ''));
                log_event('admin_login_success', 'Admin-Login erfolgreich', [
                    'user_id' => (int) $user['id'],
                    'username' => (string) $user['username'],
                ]);
                redirect('admin.php');
            }

            $errors[] = 'Benutzername oder Passwort ist falsch.';
            log_event('admin_login_error', 'Admin-Login fehlgeschlagen', [
                'username' => $username,
            ]);
        } catch (Throwable $exception) {
            $errors[] = 'Login nicht möglich: ' . $exception->getMessage();
            log_event('admin_login_error', 'Admin-Login Datenbankfehler', [
                'username' => $username,
                'error' => $exception->getMessage(),
            ]);
        }
    }
}

if (!is_admin_logged_in()):
?>
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login · Hochzeit</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Great+Vibes&family=Nunito+Sans:wght@300;400;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="css/style.css">
    <style><?= render_theme_variables($theme) ?></style>
</head>
<body>
<main class="section login-shell">
    <div class="container">
        <section class="card login-card reveal">
            <p class="eyebrow">Adminbereich</p>
            <h1>Willkommen zurück</h1>
            <p>Bitte mit Admin‑Zugangsdaten anmelden.</p>
            <p class="small-note">Beim ersten Login müssen E‑Mail und Passwort verpflichtend aktualisiert werden.</p>

            <?php foreach ($errors as $message): ?>
                <div class="alert alert-error"><?= e($message) ?></div>
            <?php endforeach; ?>

            <?php if ($defaultAdminCredentials !== null): ?>
                <div class="alert alert-warn">
                    Initialer Admin wurde erstellt (Benutzer: <strong><?= e($defaultAdminCredentials['username']) ?></strong>).
                    Das Startpasswort ist in `ADMIN_INITIAL_PASSWORD` konfigurierbar.
                </div>
            <?php endif; ?>

            <form method="post" class="form-card">
                <input type="hidden" name="action" value="login">
                <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">

                <div class="form-row">
                    <label for="username">Benutzername</label>
                    <input id="username" name="username" type="text" required>
                </div>

                <div class="form-row">
                    <label for="password">Passwort</label>
                    <input id="password" name="password" type="password" required>
                </div>

                <button class="btn" type="submit">Login</button>
            </form>

            <p class="small-note">Zur Website: <a href="index.php">Startseite öffnen</a></p>
        </section>
    </div>
</main>
<script src="js/scripts.js"></script>
</body>
</html>
<?php
exit;
endif;

$currentAdmin = get_current_admin_user();
if ($currentAdmin === null) {
    admin_logout();
    redirect('admin.php');
}

$mustCompleteSetup = admin_user_requires_first_login_setup($currentAdmin);
$_SESSION['admin_force_setup'] = $mustCompleteSetup ? 1 : 0;
if (!$mustCompleteSetup) {
    $_SESSION['admin_email'] = (string) $currentAdmin['email'];
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = (string) ($_POST['action'] ?? '');

    if (!verify_csrf($_POST['csrf_token'] ?? null)) {
        $errors[] = 'Sicherheitsprüfung fehlgeschlagen. Aktion wurde abgebrochen.';
        log_event('admin_action_error', 'Admin-Aktion mit ungültigem CSRF-Token', [
            'user_id' => (int) $currentAdmin['id'],
            'action' => $action,
        ]);
    } else {
        try {
            if ($action === 'complete_first_login') {
                if (!$mustCompleteSetup) {
                    throw new RuntimeException('Der First-Login-Setup ist bereits abgeschlossen.');
                }

                $email = strtolower(trim((string) ($_POST['email'] ?? '')));
                $newPassword = (string) ($_POST['new_password'] ?? '');
                $confirmPassword = (string) ($_POST['confirm_password'] ?? '');

                if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                    throw new RuntimeException('Bitte gib eine gültige E-Mail-Adresse ein.');
                }

                if ($newPassword !== $confirmPassword) {
                    throw new RuntimeException('Die Passwort-Bestätigung stimmt nicht überein.');
                }

                if (strlen($newPassword) < 10) {
                    throw new RuntimeException('Das neue Passwort muss mindestens 10 Zeichen lang sein.');
                }

                if (
                    preg_match('/[A-Z]/', $newPassword) !== 1
                    || preg_match('/[a-z]/', $newPassword) !== 1
                    || preg_match('/[0-9]/', $newPassword) !== 1
                ) {
                    throw new RuntimeException('Das Passwort muss Großbuchstaben, Kleinbuchstaben und Zahlen enthalten.');
                }

                $passwordHash = password_hash($newPassword, PASSWORD_DEFAULT);
                if (!is_string($passwordHash)) {
                    throw new RuntimeException('Passwort konnte nicht sicher gespeichert werden.');
                }

                $stmt = db()->prepare(
                    'UPDATE users
                     SET email = :email,
                         password_hash = :password_hash,
                         must_change_password = 0,
                         updated_at = NOW()
                     WHERE id = :id'
                );
                $stmt->execute([
                    ':email' => $email,
                    ':password_hash' => $passwordHash,
                    ':id' => (int) $currentAdmin['id'],
                ]);

                admin_mark_setup_complete($email);
                log_event('admin_first_login_complete', 'First-Login-Setup abgeschlossen', [
                    'user_id' => (int) $currentAdmin['id'],
                    'email' => $email,
                ]);
                redirect('admin.php?setup=done');
            }

            if ($mustCompleteSetup) {
                throw new RuntimeException('Bitte schließe zuerst den First-Login-Setup ab.');
            }

            switch ($action) {
                case 'create_guest':
                    $activeTab = 'tab-guests';
                    $firstName = trim((string) ($_POST['first_name'] ?? ''));
                    $lastName = trim((string) ($_POST['last_name'] ?? ''));
                    $email = strtolower(trim((string) ($_POST['email'] ?? '')));
                    $phone = trim((string) ($_POST['phone'] ?? ''));
                    $rsvpStatus = (string) ($_POST['rsvp_status'] ?? 'offen');
                    $plusOne = max(0, min(6, (int) ($_POST['plus_one'] ?? 0)));

                    if ($firstName === '' || $lastName === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
                        throw new RuntimeException('Für neue Gäste werden Vorname, Nachname und gültige E‑Mail benötigt.');
                    }

                    $stmt = db()->prepare('INSERT INTO guests (first_name, last_name, email, phone, rsvp_status, plus_one, created_at)
                                           VALUES (:first_name, :last_name, :email, :phone, :rsvp_status, :plus_one, NOW())');
                    $stmt->execute([
                        ':first_name' => $firstName,
                        ':last_name' => $lastName,
                        ':email' => $email,
                        ':phone' => $phone,
                        ':rsvp_status' => $rsvpStatus,
                        ':plus_one' => $plusOne,
                    ]);

                    $success[] = 'Gast wurde angelegt.';
                    log_event('guest_created', 'Neuer Gast angelegt', [
                        'user_id' => (int) $currentAdmin['id'],
                        'guest_email' => $email,
                        'guest_name' => $firstName . ' ' . $lastName,
                    ]);
                    break;

                case 'update_guest':
                    $activeTab = 'tab-guests';
                    $guestId = (int) ($_POST['guest_id'] ?? 0);
                    $firstName = trim((string) ($_POST['first_name'] ?? ''));
                    $lastName = trim((string) ($_POST['last_name'] ?? ''));
                    $email = strtolower(trim((string) ($_POST['email'] ?? '')));
                    $phone = trim((string) ($_POST['phone'] ?? ''));
                    $rsvpStatus = (string) ($_POST['rsvp_status'] ?? 'offen');
                    $plusOne = max(0, min(6, (int) ($_POST['plus_one'] ?? 0)));

                    if ($guestId <= 0 || $firstName === '' || $lastName === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
                        throw new RuntimeException('Ungültige Gästedaten für das Update.');
                    }

                    $stmt = db()->prepare('UPDATE guests
                                           SET first_name = :first_name,
                                               last_name = :last_name,
                                               email = :email,
                                               phone = :phone,
                                               rsvp_status = :rsvp_status,
                                               plus_one = :plus_one
                                           WHERE id = :id');
                    $stmt->execute([
                        ':first_name' => $firstName,
                        ':last_name' => $lastName,
                        ':email' => $email,
                        ':phone' => $phone,
                        ':rsvp_status' => $rsvpStatus,
                        ':plus_one' => $plusOne,
                        ':id' => $guestId,
                    ]);

                    $success[] = 'Gast wurde aktualisiert.';
                    log_event('guest_updated', 'Gastdaten aktualisiert', [
                        'user_id' => (int) $currentAdmin['id'],
                        'guest_id' => $guestId,
                        'guest_email' => $email,
                    ]);
                    break;

                case 'delete_guest':
                    $activeTab = 'tab-guests';
                    $guestId = (int) ($_POST['guest_id'] ?? 0);
                    if ($guestId <= 0) {
                        throw new RuntimeException('Ungültige Gast-ID.');
                    }

                    $stmt = db()->prepare('DELETE FROM guests WHERE id = :id');
                    $stmt->execute([':id' => $guestId]);
                    $success[] = 'Gast wurde gelöscht.';
                    log_event('guest_deleted', 'Gast gelöscht', [
                        'user_id' => (int) $currentAdmin['id'],
                        'guest_id' => $guestId,
                    ]);
                    break;

                case 'generate_qr':
                    $activeTab = 'tab-guests';
                    $guestId = (int) ($_POST['guest_id'] ?? 0);
                    $expiresAtRaw = trim((string) ($_POST['expires_at'] ?? ''));
                    $expiresAt = $expiresAtRaw !== '' ? $expiresAtRaw . ' 23:59:59' : null;

                    if ($guestId <= 0) {
                        throw new RuntimeException('Ungültige Gast-ID für QR-Erzeugung.');
                    }

                    $guestStmt = db()->prepare('SELECT id, first_name, last_name, email FROM guests WHERE id = :id LIMIT 1');
                    $guestStmt->execute([':id' => $guestId]);
                    $guest = $guestStmt->fetch();
                    if (!$guest) {
                        throw new RuntimeException('Gast nicht gefunden.');
                    }

                    $created = create_guest_qr_token($guestId, $expiresAt);
                    $success[] = 'Neuer QR‑Token erstellt: ' . $created['token'];
                    log_event('qr_created', 'Neuer QR-Token erstellt', [
                        'user_id' => (int) $currentAdmin['id'],
                        'guest_id' => $guestId,
                        'token_id' => (int) $created['id'],
                    ]);

                    $mailResult = send_guest_qr_email($guest, $created);
                    if (($mailResult['success'] ?? false) === true) {
                        $success[] = 'QR-Mail an ' . (string) $guest['email'] . ' wurde versendet.';
                        log_event('qr_email_sent', 'QR-Mail wurde automatisch versendet', [
                            'user_id' => (int) $currentAdmin['id'],
                            'guest_id' => $guestId,
                            'token_id' => (int) $created['id'],
                            'email' => (string) $guest['email'],
                        ]);
                    } else {
                        $errors[] = 'QR erstellt, aber E-Mail-Versand fehlgeschlagen: ' . (string) ($mailResult['message'] ?? 'Unbekannter Fehler');
                        log_event('qr_email_error', 'Automatischer QR-Mailversand fehlgeschlagen', [
                            'user_id' => (int) $currentAdmin['id'],
                            'guest_id' => $guestId,
                            'token_id' => (int) $created['id'],
                            'email' => (string) ($guest['email'] ?? ''),
                            'error' => (string) ($mailResult['message'] ?? ''),
                        ]);
                    }
                    break;

                case 'send_qr_mail':
                    $activeTab = 'tab-guests';
                    $guestId = (int) ($_POST['guest_id'] ?? 0);
                    if ($guestId <= 0) {
                        throw new RuntimeException('Ungültige Gast-ID für E-Mail-Versand.');
                    }

                    $mailStmt = db()->prepare(
                        'SELECT g.id, g.first_name, g.last_name, g.email, qt.id AS token_id, qt.token, qt.qr_path
                         FROM guests g
                         LEFT JOIN qr_tokens qt ON qt.id = (
                             SELECT q2.id FROM qr_tokens q2 WHERE q2.guest_id = g.id ORDER BY q2.created_at DESC LIMIT 1
                         )
                         WHERE g.id = :id
                         LIMIT 1'
                    );
                    $mailStmt->execute([':id' => $guestId]);
                    $guestMailData = $mailStmt->fetch();

                    if (!$guestMailData || empty($guestMailData['token'])) {
                        throw new RuntimeException('Kein QR-Token für diesen Gast vorhanden.');
                    }

                    $tokenData = [
                        'id' => (int) $guestMailData['token_id'],
                        'token' => (string) $guestMailData['token'],
                        'qr_path' => (string) ($guestMailData['qr_path'] ?? ''),
                        'url' => gallery_url_for_token((string) $guestMailData['token']),
                    ];
                    $mailResult = send_guest_qr_email($guestMailData, $tokenData);

                    if (($mailResult['success'] ?? false) !== true) {
                        throw new RuntimeException('QR-Mail konnte nicht versendet werden: ' . (string) ($mailResult['message'] ?? 'Unbekannter Fehler'));
                    }

                    $success[] = 'QR-Mail an ' . (string) $guestMailData['email'] . ' wurde versendet.';
                    log_event('qr_email_sent', 'QR-Mail manuell versendet', [
                        'user_id' => (int) $currentAdmin['id'],
                        'guest_id' => $guestId,
                        'token_id' => (int) $guestMailData['token_id'],
                        'email' => (string) $guestMailData['email'],
                    ]);
                    break;

                case 'toggle_token':
                    $activeTab = 'tab-guests';
                    $tokenId = (int) ($_POST['token_id'] ?? 0);
                    $newState = (int) ($_POST['state'] ?? 0);
                    if ($tokenId <= 0) {
                        throw new RuntimeException('Ungültige Token-ID.');
                    }

                    $stmt = db()->prepare('UPDATE qr_tokens SET is_active = :state WHERE id = :id');
                    $stmt->execute([
                        ':state' => $newState === 1 ? 1 : 0,
                        ':id' => $tokenId,
                    ]);

                    $success[] = 'Token-Status wurde aktualisiert.';
                    log_event('qr_token_toggled', 'Token-Status geändert', [
                        'user_id' => (int) $currentAdmin['id'],
                        'token_id' => $tokenId,
                        'new_state' => $newState === 1 ? 1 : 0,
                    ]);
                    break;

                case 'moderate_photo':
                    $activeTab = 'tab-photos';
                    $photoId = (int) ($_POST['photo_id'] ?? 0);
                    $status = (string) ($_POST['status'] ?? 'pending');

                    if ($photoId <= 0) {
                        throw new RuntimeException('Ungültige Foto-ID.');
                    }

                    if ($status === 'delete') {
                        $stmt = db()->prepare('DELETE FROM photos WHERE id = :id');
                        $stmt->execute([':id' => $photoId]);
                        $success[] = 'Fotoeintrag wurde gelöscht.';
                        log_event('photo_deleted', 'Fotoeintrag gelöscht', [
                            'user_id' => (int) $currentAdmin['id'],
                            'photo_id' => $photoId,
                        ]);
                        break;
                    }

                    if (!in_array($status, ['pending', 'approved', 'rejected'], true)) {
                        throw new RuntimeException('Ungültiger Foto-Status.');
                    }

                    $approvedAt = $status === 'approved' ? (new DateTimeImmutable())->format('Y-m-d H:i:s') : null;
                    $stmt = db()->prepare('UPDATE photos SET status = :status, approved_at = :approved_at WHERE id = :id');
                    $stmt->execute([
                        ':status' => $status,
                        ':approved_at' => $approvedAt,
                        ':id' => $photoId,
                    ]);
                    $success[] = 'Foto-Status auf "' . $status . '" gesetzt.';
                    log_event('photo_moderated', 'Foto moderiert', [
                        'user_id' => (int) $currentAdmin['id'],
                        'photo_id' => $photoId,
                        'status' => $status,
                    ]);
                    break;

                case 'save_theme':
                    $activeTab = 'tab-design';
                    $settings = [
                        'bride_name' => trim((string) ($_POST['bride_name'] ?? 'Lena')),
                        'groom_name' => trim((string) ($_POST['groom_name'] ?? 'Jonas')),
                        'hero_title' => trim((string) ($_POST['hero_title'] ?? 'Wir sagen Ja')),
                        'wedding_date' => trim((string) ($_POST['wedding_date'] ?? '2026-08-15 14:30:00')),
                        'venue_name' => trim((string) ($_POST['venue_name'] ?? 'Gut Sonnenhof')),
                        'venue_address' => trim((string) ($_POST['venue_address'] ?? 'Sonnenweg 12, 50667 Köln')),
                        'intro_text' => trim((string) ($_POST['intro_text'] ?? '')),
                        'story_text_1' => trim((string) ($_POST['story_text_1'] ?? '')),
                        'story_text_2' => trim((string) ($_POST['story_text_2'] ?? '')),
                        'timeline_1_time' => trim((string) ($_POST['timeline_1_time'] ?? '14:30')),
                        'timeline_1_title' => trim((string) ($_POST['timeline_1_title'] ?? 'Freie Trauung')),
                        'timeline_1_text' => trim((string) ($_POST['timeline_1_text'] ?? '')),
                        'timeline_2_time' => trim((string) ($_POST['timeline_2_time'] ?? '16:00')),
                        'timeline_2_title' => trim((string) ($_POST['timeline_2_title'] ?? 'Empfang & Fotospots')),
                        'timeline_2_text' => trim((string) ($_POST['timeline_2_text'] ?? '')),
                        'timeline_3_time' => trim((string) ($_POST['timeline_3_time'] ?? '18:30')),
                        'timeline_3_title' => trim((string) ($_POST['timeline_3_title'] ?? 'Dinner')),
                        'timeline_3_text' => trim((string) ($_POST['timeline_3_text'] ?? '')),
                        'timeline_4_time' => trim((string) ($_POST['timeline_4_time'] ?? '21:00')),
                        'timeline_4_title' => trim((string) ($_POST['timeline_4_title'] ?? 'Party')),
                        'timeline_4_text' => trim((string) ($_POST['timeline_4_text'] ?? '')),
                        'travel_train_text' => trim((string) ($_POST['travel_train_text'] ?? '')),
                        'travel_car_text' => trim((string) ($_POST['travel_car_text'] ?? '')),
                        'travel_nav_address' => trim((string) ($_POST['travel_nav_address'] ?? '')),
                        'dresscode' => trim((string) ($_POST['dresscode'] ?? 'Summer Chic')),
                        'stays_intro' => trim((string) ($_POST['stays_intro'] ?? '')),
                        'stay_option_1' => trim((string) ($_POST['stay_option_1'] ?? '')),
                        'stay_option_2' => trim((string) ($_POST['stay_option_2'] ?? '')),
                        'stay_option_3' => trim((string) ($_POST['stay_option_3'] ?? '')),
                        'gift_text_1' => trim((string) ($_POST['gift_text_1'] ?? '')),
                        'gift_text_2' => trim((string) ($_POST['gift_text_2'] ?? '')),
                        'playlist_text' => trim((string) ($_POST['playlist_text'] ?? '')),
                        'rsvp_deadline' => trim((string) ($_POST['rsvp_deadline'] ?? '01.07.2026')),
                        'primary_color' => trim((string) ($_POST['primary_color'] ?? '#f4d9df')),
                        'secondary_color' => trim((string) ($_POST['secondary_color'] ?? '#d5e4d7')),
                        'accent_color' => trim((string) ($_POST['accent_color'] ?? '#9fb7cf')),
                        'text_color' => trim((string) ($_POST['text_color'] ?? '#302728')),
                        'heading_font' => trim((string) ($_POST['heading_font'] ?? 'Great Vibes')),
                        'body_font' => trim((string) ($_POST['body_font'] ?? 'Nunito Sans')),
                        'hero_image' => trim((string) ($_POST['hero_image'] ?? '')),
                    ];

                    save_settings($settings);
                    $theme = get_theme_settings();
                    $success[] = 'Design- und Inhaltssettings gespeichert.';
                    log_event('theme_saved', 'Design- und Inhaltssettings gespeichert', [
                        'user_id' => (int) $currentAdmin['id'],
                    ]);
                    break;

                case 'save_system_settings':
                    $activeTab = 'tab-system';
                    $appBaseUrl = rtrim(trim((string) ($_POST['app_base_url'] ?? '')), '/');
                    $frontendEnabled = (string) ($_POST['frontend_enabled'] ?? '1');
                    $synoBaseUrl = rtrim(trim((string) ($_POST['syno_base_url'] ?? '')), '/');
                    $synoUsername = trim((string) ($_POST['syno_username'] ?? ''));
                    $synoPassword = trim((string) ($_POST['syno_password'] ?? ''));
                    $synoTargetPath = trim((string) ($_POST['syno_target_path'] ?? '/wedding-uploads'));
                    $synoVerifySsl = (string) ($_POST['syno_verify_ssl'] ?? '1');
                    $galleryMasterKey = trim((string) ($_POST['gallery_master_key'] ?? ''));

                    if ($appBaseUrl !== '' && !filter_var($appBaseUrl, FILTER_VALIDATE_URL)) {
                        throw new RuntimeException('APP URL ist ungültig. Beispiel: https://deine-domain.de');
                    }
                    if (!in_array($frontendEnabled, ['0', '1'], true)) {
                        $frontendEnabled = '1';
                    }

                    if ($synoBaseUrl !== '' && !filter_var($synoBaseUrl, FILTER_VALIDATE_URL)) {
                        throw new RuntimeException('Synology Base URL ist ungültig. Beispiel: https://nas.local:5001');
                    }

                    if ($synoTargetPath === '') {
                        $synoTargetPath = '/wedding-uploads';
                    }
                    if (!is_strong_gallery_master_key($galleryMasterKey)) {
                        $galleryMasterKey = generate_gallery_master_key(32);
                    }

                    save_settings([
                        'app_base_url' => $appBaseUrl,
                        'frontend_enabled' => $frontendEnabled,
                        'syno_base_url' => $synoBaseUrl,
                        'syno_username' => $synoUsername,
                        'syno_password' => $synoPassword,
                        'syno_target_path' => $synoTargetPath,
                        'syno_verify_ssl' => in_array(strtolower($synoVerifySsl), ['1', 'true', 'yes', 'on'], true) ? '1' : '0',
                        'gallery_master_key' => $galleryMasterKey,
                    ]);

                    $success[] = 'System- und Synology-Einstellungen wurden gespeichert.';
                    log_event('system_settings_saved', 'Systemeinstellungen gespeichert', [
                        'user_id' => (int) $currentAdmin['id'],
                    ]);
                    break;

                case 'regenerate_master_key':
                    $activeTab = 'tab-system';
                    $newMasterKey = generate_gallery_master_key(32);
                    save_settings(['gallery_master_key' => $newMasterKey]);
                    $success[] = 'Neuer Galerie Master‑Key wurde erzeugt.';
                    log_event('master_key_regenerated', 'Galerie Master-Key neu generiert', [
                        'user_id' => (int) $currentAdmin['id'],
                    ]);
                    break;

                case 'save_email_settings':
                    $activeTab = 'tab-system';
                    $mailFromName = trim((string) ($_POST['mail_from_name'] ?? 'Hochzeits-Team'));
                    $mailFromAddress = strtolower(trim((string) ($_POST['mail_from_address'] ?? '')));
                    $mailSubjectTemplate = trim((string) ($_POST['mail_subject_template'] ?? ''));
                    $mailBodyTemplate = trim((string) ($_POST['mail_body_template'] ?? ''));
                    $smtpHost = trim((string) ($_POST['smtp_host'] ?? ''));
                    $smtpPort = (int) ($_POST['smtp_port'] ?? 587);
                    $smtpEncryption = strtolower(trim((string) ($_POST['smtp_encryption'] ?? 'tls')));
                    $smtpUsername = trim((string) ($_POST['smtp_username'] ?? ''));
                    $smtpPassword = trim((string) ($_POST['smtp_password'] ?? ''));
                    $smtpTimeout = max(5, (int) ($_POST['smtp_timeout'] ?? 20));

                    if ($mailFromName === '') {
                        $mailFromName = 'Hochzeits-Team';
                    }
                    if ($mailFromAddress === '' || !filter_var($mailFromAddress, FILTER_VALIDATE_EMAIL)) {
                        throw new RuntimeException('Bitte eine gültige Absender-E-Mail angeben.');
                    }
                    if ($mailSubjectTemplate === '') {
                        throw new RuntimeException('Betreff-Vorlage darf nicht leer sein.');
                    }
                    if ($mailBodyTemplate === '') {
                        throw new RuntimeException('Mailtext-Vorlage darf nicht leer sein.');
                    }
                    if ($smtpHost === '') {
                        throw new RuntimeException('SMTP Host darf nicht leer sein.');
                    }
                    if ($smtpPort <= 0 || $smtpPort > 65535) {
                        throw new RuntimeException('SMTP Port ist ungültig.');
                    }
                    if (!in_array($smtpEncryption, ['tls', 'ssl', 'none'], true)) {
                        throw new RuntimeException('SMTP Verschlüsselung muss tls, ssl oder none sein.');
                    }
                    if ($smtpUsername === '' || $smtpPassword === '') {
                        throw new RuntimeException('SMTP Benutzername und Passwort sind erforderlich.');
                    }

                    save_settings([
                        'mail_from_name' => $mailFromName,
                        'mail_from_address' => $mailFromAddress,
                        'mail_subject_template' => $mailSubjectTemplate,
                        'mail_body_template' => $mailBodyTemplate,
                        'smtp_host' => $smtpHost,
                        'smtp_port' => (string) $smtpPort,
                        'smtp_encryption' => $smtpEncryption,
                        'smtp_username' => $smtpUsername,
                        'smtp_password' => $smtpPassword,
                        'smtp_timeout' => (string) $smtpTimeout,
                    ]);

                    $success[] = 'E-Mail- und SMTP-Einstellungen wurden gespeichert.';
                    log_event('email_settings_saved', 'E-Mail-Template im Admin gespeichert', [
                        'user_id' => (int) $currentAdmin['id'],
                        'mail_from_address' => $mailFromAddress,
                        'smtp_host' => $smtpHost,
                    ]);
                    break;

                case 'db_run_sql':
                    $activeTab = 'tab-database';
                    if (!admin_sql_console_enabled()) {
                        throw new RuntimeException('SQL-Editor ist deaktiviert. Setze ADMIN_SQL_CONSOLE_ENABLED=1, wenn du ihn wirklich brauchst.');
                    }
                    $sqlInput = trim((string) ($_POST['sql_query'] ?? ''));
                    if ($sqlInput === '') {
                        throw new RuntimeException('Bitte SQL eingeben.');
                    }

                    $previewTableInput = (string) ($_POST['db_preview_table'] ?? 'settings');
                    if (in_array($previewTableInput, admin_manageable_tables(), true)) {
                        $dbPreviewTable = $previewTableInput;
                    }

                    $sqlConsoleOutput = 'SQL ausgeführt.';
                    if (preg_match('/^(SELECT|SHOW|DESCRIBE|EXPLAIN)\\b/i', $sqlInput) === 1) {
                        $stmt = db()->query($sqlInput);
                        $sqlConsoleRows = $stmt->fetchAll();
                        if ($sqlConsoleRows !== []) {
                            $sqlConsoleColumns = array_keys($sqlConsoleRows[0]);
                        }
                        $sqlConsoleOutput = 'Abfrage erfolgreich. Zeilen: ' . count($sqlConsoleRows);
                    } else {
                        $affected = db()->exec($sqlInput);
                        $sqlConsoleOutput = 'Statement erfolgreich. Betroffene Zeilen: ' . (int) $affected;
                    }
                    log_event('admin_sql_executed', 'SQL im Admin-Editor ausgeführt', [
                        'user_id' => (int) $currentAdmin['id'],
                        'statement_prefix' => substr($sqlInput, 0, 120),
                    ]);
                    break;

                default:
                    break;
            }
        } catch (Throwable $exception) {
            $errors[] = $exception->getMessage();
            log_event('admin_action_error', 'Admin-Aktion fehlgeschlagen', [
                'user_id' => (int) $currentAdmin['id'],
                'action' => $action,
                'error' => $exception->getMessage(),
            ]);
        }
    }
}

if ($mustCompleteSetup):
?>
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Setup · Hochzeit</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Great+Vibes&family=Nunito+Sans:wght@300;400;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="css/style.css">
    <style><?= render_theme_variables($theme) ?></style>
</head>
<body>
<main class="section login-shell">
    <div class="container">
        <section class="card login-card reveal">
            <p class="eyebrow">Erster Login</p>
            <h1>Zugang absichern</h1>
            <p>Bitte hinterlege jetzt deine E‑Mail‑Adresse und ein neues Passwort. Erst danach ist das Admin‑Panel freigeschaltet.</p>

            <?php foreach ($errors as $message): ?>
                <div class="alert alert-error"><?= e($message) ?></div>
            <?php endforeach; ?>

            <?php foreach ($success as $message): ?>
                <div class="alert alert-success"><?= e($message) ?></div>
            <?php endforeach; ?>

            <form method="post" class="form-card">
                <input type="hidden" name="action" value="complete_first_login">
                <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">

                <div class="form-row">
                    <label for="email">E‑Mail</label>
                    <input id="email" name="email" type="email" required value="<?= e((string) ($currentAdmin['email'] ?? '')) ?>">
                </div>

                <div class="form-row">
                    <label for="new_password">Neues Passwort</label>
                    <input id="new_password" name="new_password" type="password" required>
                </div>

                <div class="form-row">
                    <label for="confirm_password">Passwort bestätigen</label>
                    <input id="confirm_password" name="confirm_password" type="password" required>
                </div>

                <button class="btn" type="submit">Profil speichern</button>
            </form>

            <p class="small-note">Du kannst dich bei Bedarf hier abmelden: <a href="admin.php?logout=1">Logout</a></p>
        </section>
    </div>
</main>
<script src="js/scripts.js"></script>
</body>
</html>
<?php
exit;
endif;

log_event('admin_page_view', 'Admin-Dashboard aufgerufen', [
    'user_id' => (int) $currentAdmin['id'],
]);

$manageableTables = admin_manageable_tables();
$dbPreviewTableInput = (string) ($_GET['db_table'] ?? $dbPreviewTable);
if (in_array($dbPreviewTableInput, $manageableTables, true)) {
    $dbPreviewTable = $dbPreviewTableInput;
    if (isset($_GET['db_table'])) {
        $activeTab = 'tab-database';
    }
}

$systemSynology = synology_config();
$notificationSettings = get_notification_settings();
$smtpSettings = get_smtp_settings();
$systemSettings = [
    'app_base_url' => app_base_url(),
    'frontend_enabled' => frontend_is_enabled(),
    'syno_base_url' => (string) ($systemSynology['base_url'] ?? ''),
    'syno_username' => (string) ($systemSynology['username'] ?? ''),
    'syno_password' => (string) ($systemSynology['password'] ?? ''),
    'syno_target_path' => (string) ($systemSynology['target_path'] ?? '/wedding-uploads'),
    'syno_verify_ssl' => (bool) ($systemSynology['verify_ssl'] ?? true),
    'gallery_master_key' => gallery_master_key(),
];

$mailSettings = [
    'mail_from_name' => (string) ($notificationSettings['mail_from_name'] ?? ''),
    'mail_from_address' => (string) ($notificationSettings['mail_from_address'] ?? ''),
    'mail_subject_template' => (string) ($notificationSettings['mail_subject_template'] ?? ''),
    'mail_body_template' => (string) ($notificationSettings['mail_body_template'] ?? ''),
    'smtp_host' => (string) ($smtpSettings['smtp_host'] ?? ''),
    'smtp_port' => (string) ($smtpSettings['smtp_port'] ?? '587'),
    'smtp_encryption' => (string) ($smtpSettings['smtp_encryption'] ?? 'tls'),
    'smtp_username' => (string) ($smtpSettings['smtp_username'] ?? ''),
    'smtp_password' => (string) ($smtpSettings['smtp_password'] ?? ''),
    'smtp_timeout' => (string) ($smtpSettings['smtp_timeout'] ?? '20'),
];

$stats = [
    'guests' => 0,
    'tokens' => 0,
    'photos_pending' => 0,
    'photos_total' => 0,
];

$guests = [];
$photos = [];
$tableRowCounts = [];

try {
    $stats['guests'] = (int) db()->query('SELECT COUNT(*) FROM guests')->fetchColumn();
    $stats['tokens'] = (int) db()->query('SELECT COUNT(*) FROM qr_tokens')->fetchColumn();
    $stats['photos_pending'] = (int) db()->query("SELECT COUNT(*) FROM photos WHERE status = 'pending'")->fetchColumn();
    $stats['photos_total'] = (int) db()->query('SELECT COUNT(*) FROM photos')->fetchColumn();

    $guestSql = 'SELECT g.id, g.first_name, g.last_name, g.email, g.phone, g.rsvp_status, g.plus_one,
                        qt.id AS token_id, qt.token, qt.qr_path, qt.is_active, qt.expires_at
                 FROM guests g
                 LEFT JOIN qr_tokens qt ON qt.id = (
                     SELECT q2.id FROM qr_tokens q2 WHERE q2.guest_id = g.id ORDER BY q2.created_at DESC LIMIT 1
                 )
                 ORDER BY g.last_name, g.first_name';
    $guests = db()->query($guestSql)->fetchAll();

    $photoSql = 'SELECT p.id, p.original_name, p.file_path, p.status, p.uploaded_at,
                        g.first_name, g.last_name
                 FROM photos p
                 LEFT JOIN guests g ON g.id = p.guest_id
                 ORDER BY p.uploaded_at DESC
                 LIMIT 120';
    $photos = db()->query($photoSql)->fetchAll();

    foreach ($manageableTables as $tableName) {
        if (!admin_valid_identifier($tableName)) {
            continue;
        }
        $tableRowCounts[$tableName] = (int) db()->query('SELECT COUNT(*) FROM `' . $tableName . '`')->fetchColumn();
    }

    if (in_array($dbPreviewTable, $manageableTables, true) && admin_valid_identifier($dbPreviewTable)) {
        $dbPreviewColumns = admin_fetch_table_columns($dbPreviewTable);
        $dbPreviewRows = db()->query('SELECT * FROM `' . $dbPreviewTable . '` LIMIT 120')->fetchAll();
    }

    $recentLogs = db()->query(
        'SELECT event_type, message, ip_address, created_at, context_json
         FROM activity_logs
         ORDER BY id DESC
         LIMIT 160'
    )->fetchAll();
} catch (Throwable $exception) {
    $errors[] = 'Dashboarddaten konnten nicht geladen werden: ' . $exception->getMessage();
}
?>
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Panel · Hochzeit</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Great+Vibes&family=Nunito+Sans:wght@300;400;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="css/style.css">
    <style><?= render_theme_variables($theme) ?></style>
</head>
<body>
<header class="site-header compact-header">
    <div class="container nav-wrap">
        <a class="brand" href="index.php">Hochzeits‑Website</a>
        <nav class="main-nav is-open">
            <a href="index.php" target="_blank" rel="noopener">Website öffnen</a>
            <a href="admin.php?logout=1">Logout</a>
        </nav>
    </div>
</header>

<main class="section">
    <div class="container">
        <section class="section-head reveal">
            <p class="eyebrow">Admin Panel</p>
            <h1>Steuerzentrale</h1>
            <p>
                Eingeloggt als <?= e((string) $currentAdmin['username']) ?>
                <?php if (!empty($currentAdmin['email'])): ?>
                    · <?= e((string) $currentAdmin['email']) ?>
                <?php endif; ?>
            </p>
        </section>

        <?php foreach ($errors as $message): ?>
            <div class="alert alert-error"><?= e($message) ?></div>
        <?php endforeach; ?>

        <?php foreach ($success as $message): ?>
            <div class="alert alert-success"><?= e($message) ?></div>
        <?php endforeach; ?>

        <section class="stats-grid reveal">
            <article class="card stat-card">
                <p>Gäste</p>
                <strong><?= e((string) $stats['guests']) ?></strong>
            </article>
            <article class="card stat-card">
                <p>QR‑Tokens</p>
                <strong><?= e((string) $stats['tokens']) ?></strong>
            </article>
            <article class="card stat-card">
                <p>Fotos gesamt</p>
                <strong><?= e((string) $stats['photos_total']) ?></strong>
            </article>
            <article class="card stat-card">
                <p>Moderation offen</p>
                <strong><?= e((string) $stats['photos_pending']) ?></strong>
            </article>
        </section>

        <section class="admin-tabs card reveal">
            <div class="tab-nav">
                <button type="button" class="tab-btn <?= $activeTab === 'tab-guests' ? 'is-active' : '' ?>" data-tab-target="tab-guests">Gäste & QR</button>
                <button type="button" class="tab-btn <?= $activeTab === 'tab-photos' ? 'is-active' : '' ?>" data-tab-target="tab-photos">Fotos</button>
                <button type="button" class="tab-btn <?= $activeTab === 'tab-design' ? 'is-active' : '' ?>" data-tab-target="tab-design">Design</button>
                <button type="button" class="tab-btn <?= $activeTab === 'tab-system' ? 'is-active' : '' ?>" data-tab-target="tab-system">System</button>
                <button type="button" class="tab-btn <?= $activeTab === 'tab-database' ? 'is-active' : '' ?>" data-tab-target="tab-database">Datenbank</button>
                <button type="button" class="tab-btn <?= $activeTab === 'tab-logs' ? 'is-active' : '' ?>" data-tab-target="tab-logs">Logs & Statistik</button>
            </div>

            <div class="tab-content <?= $activeTab === 'tab-guests' ? 'is-active' : '' ?>" id="tab-guests">
                <h2>Gast anlegen</h2>
                <form method="post" class="admin-form-grid">
                    <input type="hidden" name="action" value="create_guest">
                    <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
                    <input type="text" name="first_name" placeholder="Vorname" required>
                    <input type="text" name="last_name" placeholder="Nachname" required>
                    <input type="email" name="email" placeholder="E‑Mail" required>
                    <input type="text" name="phone" placeholder="Telefon">
                    <select name="rsvp_status">
                        <option value="offen">offen</option>
                        <option value="zugesagt">zugesagt</option>
                        <option value="abgesagt">abgesagt</option>
                    </select>
                    <input type="number" name="plus_one" value="0" min="0" max="6">
                    <button class="btn" type="submit">Gast speichern</button>
                </form>

                <h3>Bestehende Gäste</h3>
                <?php if ($guests === []): ?>
                    <p>Keine Gäste vorhanden.</p>
                <?php else: ?>
                    <div class="table-wrap">
                        <table class="simple-table compact-table">
                            <thead>
                            <tr>
                                <th>Gast</th>
                                <th>RSVP</th>
                                <th>QR</th>
                                <th>Aktionen</th>
                            </tr>
                            </thead>
                            <tbody>
                            <?php foreach ($guests as $guest): ?>
                                <tr>
                                    <td>
                                        <form method="post" class="inline-grid-form">
                                            <input type="hidden" name="action" value="update_guest">
                                            <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
                                            <input type="hidden" name="guest_id" value="<?= e((string) $guest['id']) ?>">
                                            <input type="text" name="first_name" value="<?= e($guest['first_name']) ?>" required>
                                            <input type="text" name="last_name" value="<?= e($guest['last_name']) ?>" required>
                                            <input type="email" name="email" value="<?= e($guest['email']) ?>" required>
                                            <input type="text" name="phone" value="<?= e($guest['phone']) ?>">
                                            <select name="rsvp_status">
                                                <option value="offen" <?= $guest['rsvp_status'] === 'offen' ? 'selected' : '' ?>>offen</option>
                                                <option value="zugesagt" <?= $guest['rsvp_status'] === 'zugesagt' ? 'selected' : '' ?>>zugesagt</option>
                                                <option value="abgesagt" <?= $guest['rsvp_status'] === 'abgesagt' ? 'selected' : '' ?>>abgesagt</option>
                                            </select>
                                            <input type="number" name="plus_one" value="<?= e((string) $guest['plus_one']) ?>" min="0" max="6">
                                            <button class="btn btn-soft" type="submit">Update</button>
                                        </form>
                                    </td>
                                    <td><?= e($guest['rsvp_status']) ?></td>
                                    <td>
                                        <?php if (!empty($guest['token'])): ?>
                                            <code><?= e(substr((string) $guest['token'], 0, 12)) ?>...</code>
                                            <?php if (!empty($guest['qr_path']) && is_file(__DIR__ . '/' . $guest['qr_path'])): ?>
                                                <a href="<?= e($guest['qr_path']) ?>" target="_blank" rel="noopener">QR‑Code</a>
                                            <?php endif; ?>
                                            <div>
                                                <form method="post" class="inline-actions">
                                                    <input type="hidden" name="action" value="toggle_token">
                                                    <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
                                                    <input type="hidden" name="token_id" value="<?= e((string) $guest['token_id']) ?>">
                                                    <input type="hidden" name="state" value="<?= (int) $guest['is_active'] === 1 ? '0' : '1' ?>">
                                                    <button class="btn btn-soft" type="submit"><?= (int) $guest['is_active'] === 1 ? 'Deaktivieren' : 'Aktivieren' ?></button>
                                                </form>
                                                <form method="post" class="inline-actions">
                                                    <input type="hidden" name="action" value="send_qr_mail">
                                                    <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
                                                    <input type="hidden" name="guest_id" value="<?= e((string) $guest['id']) ?>">
                                                    <button class="btn btn-soft" type="submit">QR-Mail senden</button>
                                                </form>
                                            </div>
                                        <?php else: ?>
                                            <span class="small-note">Noch kein Token</span>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <form method="post" class="inline-actions">
                                            <input type="hidden" name="action" value="generate_qr">
                                            <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
                                            <input type="hidden" name="guest_id" value="<?= e((string) $guest['id']) ?>">
                                            <input type="date" name="expires_at" title="Optionales Ablaufdatum">
                                            <button class="btn" type="submit">Neuer QR</button>
                                        </form>
                                        <form method="post" class="inline-actions" onsubmit="return confirm('Gast wirklich löschen?');">
                                            <input type="hidden" name="action" value="delete_guest">
                                            <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
                                            <input type="hidden" name="guest_id" value="<?= e((string) $guest['id']) ?>">
                                            <button class="btn btn-danger" type="submit">Löschen</button>
                                        </form>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>
            </div>

            <div class="tab-content <?= $activeTab === 'tab-photos' ? 'is-active' : '' ?>" id="tab-photos">
                <h2>Foto-Moderation</h2>
                <p>Status steuert die Sichtbarkeit auf der öffentlichen Startseite. In der geschützten Galerie sind Uploads bereits sichtbar.</p>
                <?php if ($photos === []): ?>
                    <p>Keine Fotos gefunden.</p>
                <?php else: ?>
                    <div class="photo-admin-grid">
                        <?php foreach ($photos as $photo): ?>
                            <article class="card photo-admin-item">
                                <img src="<?= e($photo['file_path']) ?>" alt="<?= e($photo['original_name']) ?>" loading="lazy" class="lazy">
                                <h3><?= e($photo['original_name']) ?></h3>
                                <p>Von: <?= e(trim(($photo['first_name'] ?? '') . ' ' . ($photo['last_name'] ?? ''))) ?></p>
                                <p>Status: <strong><?= e($photo['status']) ?></strong></p>
                                <p><?= e((new DateTimeImmutable($photo['uploaded_at']))->format('d.m.Y H:i')) ?></p>
                                <form method="post" class="inline-actions">
                                    <input type="hidden" name="action" value="moderate_photo">
                                    <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
                                    <input type="hidden" name="photo_id" value="<?= e((string) $photo['id']) ?>">
                                    <button class="btn" type="submit" name="status" value="approved">Freigeben</button>
                                    <button class="btn btn-soft" type="submit" name="status" value="rejected">Ablehnen</button>
                                    <button class="btn btn-danger" type="submit" name="status" value="delete">Löschen</button>
                                </form>
                            </article>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
            </div>

            <div class="tab-content <?= $activeTab === 'tab-design' ? 'is-active' : '' ?>" id="tab-design">
                <h2>Design & Inhalte</h2>
                <form method="post" class="admin-form-grid long-grid">
                    <input type="hidden" name="action" value="save_theme">
                    <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">

                    <label>Vorname Partner:in A
                        <input type="text" name="bride_name" value="<?= e((string) $theme['bride_name']) ?>">
                    </label>
                    <label>Vorname Partner:in B
                        <input type="text" name="groom_name" value="<?= e((string) $theme['groom_name']) ?>">
                    </label>
                    <label>Hero Titel
                        <input type="text" name="hero_title" value="<?= e((string) $theme['hero_title']) ?>">
                    </label>
                    <label>Datum/Zeit (YYYY-MM-DD HH:MM:SS)
                        <input type="text" name="wedding_date" value="<?= e((string) $theme['wedding_date']) ?>">
                    </label>
                    <label>Locationname
                        <input type="text" name="venue_name" value="<?= e((string) $theme['venue_name']) ?>">
                    </label>
                    <label>Adresse
                        <input type="text" name="venue_address" value="<?= e((string) $theme['venue_address']) ?>">
                    </label>
                    <label>Introtext
                        <textarea name="intro_text" rows="3"><?= e((string) $theme['intro_text']) ?></textarea>
                    </label>
                    <label>Unsere Story · Absatz 1
                        <textarea name="story_text_1" rows="4"><?= e((string) ($theme['story_text_1'] ?? '')) ?></textarea>
                    </label>
                    <label>Unsere Story · Absatz 2
                        <textarea name="story_text_2" rows="3"><?= e((string) ($theme['story_text_2'] ?? '')) ?></textarea>
                    </label>
                    <label>Tagesablauf 1 · Uhrzeit
                        <input type="text" name="timeline_1_time" value="<?= e((string) ($theme['timeline_1_time'] ?? '14:30')) ?>" placeholder="14:30">
                    </label>
                    <label>Tagesablauf 1 · Titel
                        <input type="text" name="timeline_1_title" value="<?= e((string) ($theme['timeline_1_title'] ?? 'Freie Trauung')) ?>">
                    </label>
                    <label>Tagesablauf 1 · Beschreibung
                        <textarea name="timeline_1_text" rows="3"><?= e((string) ($theme['timeline_1_text'] ?? '')) ?></textarea>
                    </label>
                    <label>Tagesablauf 2 · Uhrzeit
                        <input type="text" name="timeline_2_time" value="<?= e((string) ($theme['timeline_2_time'] ?? '16:00')) ?>" placeholder="16:00">
                    </label>
                    <label>Tagesablauf 2 · Titel
                        <input type="text" name="timeline_2_title" value="<?= e((string) ($theme['timeline_2_title'] ?? 'Empfang & Fotospots')) ?>">
                    </label>
                    <label>Tagesablauf 2 · Beschreibung
                        <textarea name="timeline_2_text" rows="3"><?= e((string) ($theme['timeline_2_text'] ?? '')) ?></textarea>
                    </label>
                    <label>Tagesablauf 3 · Uhrzeit
                        <input type="text" name="timeline_3_time" value="<?= e((string) ($theme['timeline_3_time'] ?? '18:30')) ?>" placeholder="18:30">
                    </label>
                    <label>Tagesablauf 3 · Titel
                        <input type="text" name="timeline_3_title" value="<?= e((string) ($theme['timeline_3_title'] ?? 'Dinner')) ?>">
                    </label>
                    <label>Tagesablauf 3 · Beschreibung
                        <textarea name="timeline_3_text" rows="3"><?= e((string) ($theme['timeline_3_text'] ?? '')) ?></textarea>
                    </label>
                    <label>Tagesablauf 4 · Uhrzeit
                        <input type="text" name="timeline_4_time" value="<?= e((string) ($theme['timeline_4_time'] ?? '21:00')) ?>" placeholder="21:00">
                    </label>
                    <label>Tagesablauf 4 · Titel
                        <input type="text" name="timeline_4_title" value="<?= e((string) ($theme['timeline_4_title'] ?? 'Party')) ?>">
                    </label>
                    <label>Tagesablauf 4 · Beschreibung
                        <textarea name="timeline_4_text" rows="3"><?= e((string) ($theme['timeline_4_text'] ?? '')) ?></textarea>
                    </label>
                    <label>Anreise · Text Bahn
                        <textarea name="travel_train_text" rows="2"><?= e((string) ($theme['travel_train_text'] ?? '')) ?></textarea>
                    </label>
                    <label>Anreise · Text Auto
                        <textarea name="travel_car_text" rows="2"><?= e((string) ($theme['travel_car_text'] ?? '')) ?></textarea>
                    </label>
                    <label>Anreise · Navi-Adresse
                        <input type="text" name="travel_nav_address" value="<?= e((string) ($theme['travel_nav_address'] ?? '')) ?>">
                    </label>
                    <label>Dresscode
                        <input type="text" name="dresscode" value="<?= e((string) ($theme['dresscode'] ?? 'Summer Chic')) ?>">
                    </label>
                    <label>Unterkünfte · Intro
                        <textarea name="stays_intro" rows="2"><?= e((string) ($theme['stays_intro'] ?? '')) ?></textarea>
                    </label>
                    <label>Unterkunft 1
                        <input type="text" name="stay_option_1" value="<?= e((string) ($theme['stay_option_1'] ?? '')) ?>">
                    </label>
                    <label>Unterkunft 2
                        <input type="text" name="stay_option_2" value="<?= e((string) ($theme['stay_option_2'] ?? '')) ?>">
                    </label>
                    <label>Unterkunft 3
                        <input type="text" name="stay_option_3" value="<?= e((string) ($theme['stay_option_3'] ?? '')) ?>">
                    </label>
                    <label>Geschenke · Text 1
                        <textarea name="gift_text_1" rows="3"><?= e((string) ($theme['gift_text_1'] ?? '')) ?></textarea>
                    </label>
                    <label>Geschenke · Text 2
                        <textarea name="gift_text_2" rows="3"><?= e((string) ($theme['gift_text_2'] ?? '')) ?></textarea>
                    </label>
                    <label>Playlist-Text
                        <textarea name="playlist_text" rows="3"><?= e((string) ($theme['playlist_text'] ?? '')) ?></textarea>
                    </label>
                    <label>RSVP Deadline (z. B. 01.07.2026)
                        <input type="text" name="rsvp_deadline" value="<?= e((string) ($theme['rsvp_deadline'] ?? '01.07.2026')) ?>">
                    </label>
                    <label>Hero Bild URL
                        <input type="url" name="hero_image" value="<?= e((string) $theme['hero_image']) ?>">
                    </label>
                    <label>Primärfarbe
                        <input type="color" name="primary_color" value="<?= e((string) $theme['primary_color']) ?>">
                    </label>
                    <label>Sekundärfarbe
                        <input type="color" name="secondary_color" value="<?= e((string) $theme['secondary_color']) ?>">
                    </label>
                    <label>Akzentfarbe
                        <input type="color" name="accent_color" value="<?= e((string) $theme['accent_color']) ?>">
                    </label>
                    <label>Textfarbe
                        <input type="color" name="text_color" value="<?= e((string) $theme['text_color']) ?>">
                    </label>
                    <label>Heading Font
                        <input type="text" name="heading_font" value="<?= e((string) $theme['heading_font']) ?>">
                    </label>
                    <label>Body Font
                        <input type="text" name="body_font" value="<?= e((string) $theme['body_font']) ?>">
                    </label>

                    <button class="btn" type="submit">Settings speichern</button>
                </form>

                <p class="small-note">Design-Werte werden in der Tabelle `settings` gespeichert.</p>
            </div>

            <div class="tab-content <?= $activeTab === 'tab-system' ? 'is-active' : '' ?>" id="tab-system">
                <h2>System & Synology</h2>
                <form method="post" class="admin-form-grid long-grid">
                    <input type="hidden" name="action" value="save_system_settings">
                    <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">

                    <label>APP URL (für QR-Links)
                        <input type="url" name="app_base_url" value="<?= e((string) $systemSettings['app_base_url']) ?>" placeholder="https://deine-domain.de">
                    </label>
                    <label>Frontend
                        <select name="frontend_enabled">
                            <option value="1" <?= $systemSettings['frontend_enabled'] ? 'selected' : '' ?>>Aktiv (Startseite sichtbar)</option>
                            <option value="0" <?= !$systemSettings['frontend_enabled'] ? 'selected' : '' ?>>Aus (nur Galerie‑Login)</option>
                        </select>
                    </label>
                    <label>Synology Base URL
                        <input type="url" name="syno_base_url" value="<?= e((string) $systemSettings['syno_base_url']) ?>" placeholder="https://nas.local:5001">
                    </label>
                    <label>Synology Benutzername
                        <input type="text" name="syno_username" value="<?= e((string) $systemSettings['syno_username']) ?>">
                    </label>
                    <label>Synology Passwort
                        <input type="text" name="syno_password" value="<?= e((string) $systemSettings['syno_password']) ?>">
                    </label>
                    <label>Synology Zielpfad
                        <input type="text" name="syno_target_path" value="<?= e((string) $systemSettings['syno_target_path']) ?>" placeholder="/wedding-uploads">
                    </label>
                    <label>SSL prüfen
                        <select name="syno_verify_ssl">
                            <option value="1" <?= $systemSettings['syno_verify_ssl'] ? 'selected' : '' ?>>Ja</option>
                            <option value="0" <?= !$systemSettings['syno_verify_ssl'] ? 'selected' : '' ?>>Nein</option>
                        </select>
                    </label>
                    <label>Galerie Master‑Key
                        <input type="text" name="gallery_master_key" value="<?= e((string) $systemSettings['gallery_master_key']) ?>" placeholder="MASTER-KEY-CHANGE-ME">
                    </label>

                    <button class="btn" type="submit">Systemsettings speichern</button>
                </form>
                <form method="post" class="inline-actions">
                    <input type="hidden" name="action" value="regenerate_master_key">
                    <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
                    <button class="btn btn-soft" type="submit">Master‑Key neu generieren (32 Zeichen)</button>
                </form>

                <p class="small-note">Diese Werte werden in MySQL (`settings`) gespeichert und beim Upload genutzt.</p>

                <h3>QR-Mail Vorlagen</h3>
                <form method="post" class="admin-form-grid long-grid">
                    <input type="hidden" name="action" value="save_email_settings">
                    <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">

                    <label>Absendername
                        <input type="text" name="mail_from_name" value="<?= e((string) $mailSettings['mail_from_name']) ?>">
                    </label>
                    <label>Absender-E-Mail
                        <input type="email" name="mail_from_address" value="<?= e((string) $mailSettings['mail_from_address']) ?>">
                    </label>
                    <label>SMTP Host
                        <input type="text" name="smtp_host" value="<?= e((string) $mailSettings['smtp_host']) ?>" placeholder="smtp.gmail.com">
                    </label>
                    <label>SMTP Port
                        <input type="number" name="smtp_port" min="1" max="65535" value="<?= e((string) $mailSettings['smtp_port']) ?>">
                    </label>
                    <label>SMTP Verschlüsselung
                        <select name="smtp_encryption">
                            <option value="tls" <?= (string) $mailSettings['smtp_encryption'] === 'tls' ? 'selected' : '' ?>>TLS (STARTTLS)</option>
                            <option value="ssl" <?= (string) $mailSettings['smtp_encryption'] === 'ssl' ? 'selected' : '' ?>>SSL</option>
                            <option value="none" <?= (string) $mailSettings['smtp_encryption'] === 'none' ? 'selected' : '' ?>>Keine</option>
                        </select>
                    </label>
                    <label>SMTP Benutzername
                        <input type="text" name="smtp_username" value="<?= e((string) $mailSettings['smtp_username']) ?>">
                    </label>
                    <label>SMTP Passwort
                        <input type="text" name="smtp_password" value="<?= e((string) $mailSettings['smtp_password']) ?>">
                    </label>
                    <label>SMTP Timeout (Sekunden)
                        <input type="number" name="smtp_timeout" min="5" max="120" value="<?= e((string) $mailSettings['smtp_timeout']) ?>">
                    </label>
                    <label>Mail-Betreff
                        <input type="text" name="mail_subject_template" value="<?= e((string) $mailSettings['mail_subject_template']) ?>">
                    </label>
                    <label>Mail-Text (Platzhalter erlaubt)
                        <textarea name="mail_body_template" rows="10"><?= e((string) $mailSettings['mail_body_template']) ?></textarea>
                    </label>

                    <button class="btn" type="submit">E-Mail-Template speichern</button>
                </form>
                <p class="small-note">Platzhalter: `{{guest_name}}`, `{{gallery_url}}`, `{{upload_url}}`, `{{qr_image_url}}`, `{{token}}`, `{{couple_names}}`</p>
            </div>

            <div class="tab-content <?= $activeTab === 'tab-database' ? 'is-active' : '' ?>" id="tab-database">
                <h2>Datenbank-Editor</h2>
                <?php if (!admin_sql_console_enabled()): ?>
                    <div class="alert alert-warn">
                        SQL-Editor ist deaktiviert (sicherer Default). Wenn du ihn wirklich brauchst: setze <code>ADMIN_SQL_CONSOLE_ENABLED=1</code>.
                    </div>
                <?php else: ?>
                    <p>Direktzugriff auf SQL (nur Admin). Damit kannst du alle Inhalte der MySQL-Datenbank bearbeiten.</p>

                    <form method="post" class="form-card">
                        <input type="hidden" name="action" value="db_run_sql">
                        <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
                        <input type="hidden" name="db_preview_table" value="<?= e($dbPreviewTable) ?>">
                        <div class="form-row">
                            <label for="sql_query">SQL Statement</label>
                            <textarea id="sql_query" name="sql_query" rows="7" placeholder="z. B. SELECT * FROM settings; oder UPDATE settings SET setting_value='...' WHERE setting_key='...';"></textarea>
                        </div>
                        <button class="btn" type="submit">SQL ausführen</button>
                    </form>

                    <?php if ($sqlConsoleOutput !== ''): ?>
                        <div class="alert alert-success"><?= e($sqlConsoleOutput) ?></div>
                    <?php endif; ?>

                    <?php if ($sqlConsoleRows !== []): ?>
                        <div class="table-wrap">
                            <table class="simple-table compact-table">
                                <thead>
                                <tr>
                                    <?php foreach ($sqlConsoleColumns as $column): ?>
                                        <th><?= e($column) ?></th>
                                    <?php endforeach; ?>
                                </tr>
                                </thead>
                                <tbody>
                                <?php foreach ($sqlConsoleRows as $row): ?>
                                    <tr>
                                        <?php foreach ($sqlConsoleColumns as $column): ?>
                                            <td><?= e((string) ($row[$column] ?? '')) ?></td>
                                        <?php endforeach; ?>
                                    </tr>
                                <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    <?php endif; ?>
                <?php endif; ?>

                <h3>Tabellenvorschau</h3>
                <div class="inline-actions">
                    <?php foreach ($manageableTables as $tableName): ?>
                        <a class="btn btn-soft" href="admin.php?db_table=<?= e($tableName) ?>">
                            <?= e($tableName) ?> (<?= e((string) ($tableRowCounts[$tableName] ?? 0)) ?>)
                        </a>
                    <?php endforeach; ?>
                </div>

                <p class="small-note">Aktuelle Tabelle: <strong><?= e($dbPreviewTable) ?></strong> (max. 120 Zeilen)</p>
                <?php if ($dbPreviewColumns !== []): ?>
                    <div class="table-wrap">
                        <table class="simple-table compact-table">
                            <thead>
                            <tr>
                                <?php foreach ($dbPreviewColumns as $column): ?>
                                    <th><?= e((string) $column['COLUMN_NAME']) ?></th>
                                <?php endforeach; ?>
                            </tr>
                            </thead>
                            <tbody>
                            <?php if ($dbPreviewRows === []): ?>
                                <tr>
                                    <td colspan="<?= e((string) count($dbPreviewColumns)) ?>">Keine Datensätze.</td>
                                </tr>
                            <?php else: ?>
                                <?php foreach ($dbPreviewRows as $row): ?>
                                    <tr>
                                        <?php foreach ($dbPreviewColumns as $column): ?>
                                            <?php $columnName = (string) $column['COLUMN_NAME']; ?>
                                            <td><?= e((string) ($row[$columnName] ?? '')) ?></td>
                                        <?php endforeach; ?>
                                    </tr>
                                <?php endforeach; ?>
                            <?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>
            </div>

            <div class="tab-content <?= $activeTab === 'tab-logs' ? 'is-active' : '' ?>" id="tab-logs">
                <h2>Logs & Statistik</h2>
                <p>Hier siehst du die vollständige Seitenprotokollierung inkl. Uploads, Login-Events und Admin-Aktionen.</p>

                <?php if ($recentLogs === []): ?>
                    <div class="card"><p>Noch keine Logeinträge vorhanden.</p></div>
                <?php else: ?>
                    <div class="table-wrap">
                        <table class="simple-table compact-table">
                            <thead>
                            <tr>
                                <th>Zeit</th>
                                <th>Typ</th>
                                <th>Nachricht</th>
                                <th>IP</th>
                                <th>Kontext</th>
                            </tr>
                            </thead>
                            <tbody>
                            <?php foreach ($recentLogs as $log): ?>
                                <tr>
                                    <td><?= e((new DateTimeImmutable((string) $log['created_at']))->format('d.m.Y H:i:s')) ?></td>
                                    <td><code><?= e((string) $log['event_type']) ?></code></td>
                                    <td><?= e((string) $log['message']) ?></td>
                                    <td><?= e((string) ($log['ip_address'] ?? '')) ?></td>
                                    <td><code><?= e((string) ($log['context_json'] ?? '')) ?></code></td>
                                </tr>
                            <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>
            </div>
        </section>
    </div>
</main>

<script src="js/scripts.js"></script>
</body>
</html>
