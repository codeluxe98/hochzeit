<?php
declare(strict_types=1);

require_once __DIR__ . '/config.php';

$theme = get_theme_settings();
$error = '';
$notice = '';
$guestFolders = [];

log_event('page_view', 'Galerie-Seite aufgerufen', [
    'page' => 'gallery',
    'method' => $_SERVER['REQUEST_METHOD'] ?? 'GET',
    'is_master' => has_gallery_master_access() ? 1 : 0,
]);

if (isset($_GET['logout']) && $_GET['logout'] === '1') {
    log_event('gallery_logout', 'Galeriezugang abgemeldet', [
        'is_master' => has_gallery_master_access() ? 1 : 0,
    ]);
    clear_gallery_access();
    redirect('gallery.php');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'token_login') {
    if (!verify_csrf($_POST['csrf_token'] ?? null)) {
        $error = 'Sicherheitsprüfung fehlgeschlagen. Bitte erneut versuchen.';
        log_event('gallery_login_error', 'Galerie-Login mit ungültigem CSRF-Token');
    } else {
        $tokenInputRaw = trim((string) ($_POST['token'] ?? ''));
        if (is_gallery_master_key($tokenInputRaw)) {
            set_gallery_master_access();
            log_event('gallery_master_login', 'Master-Zugang zur Galerie aktiviert');
            redirect('gallery.php');
        }

        $tokenInput = strtolower($tokenInputRaw);
        $tokenRow = validate_gallery_token($tokenInput);
        if ($tokenRow) {
            set_gallery_access($tokenRow);
            log_event('gallery_login_success', 'Galerie-Login mit Gast-Token erfolgreich', [
                'guest_id' => (int) $tokenRow['guest_id'],
                'token_id' => (int) $tokenRow['id'],
            ]);
            redirect('gallery.php');
        }

        $error = 'Token ungültig oder abgelaufen. Bitte prüfe deinen QR-Code.';
        log_event('gallery_login_error', 'Galerie-Login fehlgeschlagen', [
            'token_prefix' => substr($tokenInput, 0, 8),
        ]);
    }
}

if (isset($_GET['token']) && is_string($_GET['token'])) {
    $tokenFromUrl = strtolower(trim($_GET['token']));
    $tokenRow = validate_gallery_token($tokenFromUrl);

    if ($tokenRow) {
        set_gallery_access($tokenRow);
        log_event('gallery_login_success', 'Galerie-Login per URL-Token erfolgreich', [
            'guest_id' => (int) $tokenRow['guest_id'],
            'token_id' => (int) $tokenRow['id'],
        ]);
        redirect('gallery.php');
    }

    $error = 'Dieser Galerie-Link ist nicht (mehr) gültig.';
    log_event('gallery_login_error', 'Ungültiger Galerie-Link verwendet', [
        'token_prefix' => substr($tokenFromUrl, 0, 8),
    ]);
}

// Intentionally no master-key login via URL parameters. Query strings leak too easily (history, logs, referrer).

$access = get_gallery_access();
$isMasterAccess = has_gallery_master_access();
$approvedPhotos = [];
$ownUploads = [];

if ($access !== null || $isMasterAccess) {
    try {
        $photoSql = 'SELECT p.file_path, p.original_name, p.uploaded_at, p.status, p.synology_path,
                            g.id AS guest_id, g.first_name, g.last_name
                     FROM photos p
                     LEFT JOIN guests g ON g.id = p.guest_id';
        $photoSql .= $isMasterAccess ? ' ORDER BY p.uploaded_at DESC LIMIT 240' : ' ORDER BY p.uploaded_at DESC LIMIT 160';
        $approvedStmt = db()->query($photoSql);
        $approvedPhotos = $approvedStmt->fetchAll();

        foreach ($approvedPhotos as $photo) {
            $folderGuestId = (int) ($photo['guest_id'] ?? 0);
            $folderGuestName = trim((string) ($photo['first_name'] ?? '') . ' ' . (string) ($photo['last_name'] ?? ''));
            if ($folderGuestName === '') {
                $folderGuestName = $folderGuestId > 0 ? 'Gast #' . $folderGuestId : 'Unbekannter Gast';
            }
            $folderKey = $folderGuestId > 0 ? 'guest_' . $folderGuestId : 'guest_unknown';

            if (!isset($guestFolders[$folderKey])) {
                $guestFolders[$folderKey] = [
                    'guest_name' => $folderGuestName,
                    'guest_id' => $folderGuestId,
                    'count' => 0,
                    'last_upload' => (string) ($photo['uploaded_at'] ?? ''),
                    'cover' => (string) ($photo['file_path'] ?? ''),
                    'photos' => [],
                ];
            }

            $guestFolders[$folderKey]['count']++;
            if (count($guestFolders[$folderKey]['photos']) < 6) {
                $guestFolders[$folderKey]['photos'][] = (string) ($photo['file_path'] ?? '');
            }
            if ((string) $photo['uploaded_at'] > (string) $guestFolders[$folderKey]['last_upload']) {
                $guestFolders[$folderKey]['last_upload'] = (string) $photo['uploaded_at'];
            }
        }

        if ($access !== null) {
            $ownStmt = db()->prepare('SELECT file_path, original_name, status, uploaded_at FROM photos WHERE token_id = :token_id ORDER BY uploaded_at DESC LIMIT 20');
            $ownStmt->execute([':token_id' => $access['token_id']]);
            $ownUploads = $ownStmt->fetchAll();
        }
    } catch (Throwable $exception) {
        $notice = 'Galerie konnte nicht vollständig geladen werden: ' . $exception->getMessage();
    }
}
?>
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>QR‑Galerie · Hochzeit</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Great+Vibes&family=Nunito+Sans:wght@300;400;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="css/style.css">
    <style><?= render_theme_variables($theme) ?></style>
</head>
<body>
<header class="site-header compact-header">
    <div class="container nav-wrap">
        <a class="brand" href="index.php">Zur Hochzeit</a>
        <?php if ($access !== null || $isMasterAccess): ?>
            <nav class="main-nav is-open">
                <?php if ($access !== null || $isMasterAccess): ?>
                    <a href="upload.php" class="btn btn-soft">Foto hochladen</a>
                <?php endif; ?>
                <a href="gallery.php?logout=1">Abmelden</a>
            </nav>
        <?php endif; ?>
    </div>
</header>

<main class="section">
    <div class="container">
        <?php if ($access === null && !$isMasterAccess): ?>
            <div class="card gate-card reveal">
                <p class="eyebrow">Private Galerie</p>
                <h1>Dein QR‑Zugang</h1>
                <p>Scanne den QR‑Code aus deiner Einladung oder gib den Token manuell ein. Mit dem Master‑Key ist der Gesamtzugriff möglich.</p>

                <?php if ($error !== ''): ?>
                    <div class="alert alert-error"><?= e($error) ?></div>
                <?php endif; ?>

                <form method="post" class="form-card narrow-form">
                    <input type="hidden" name="action" value="token_login">
                    <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
                    <div class="form-row">
                        <label for="token">Token</label>
                        <input id="token" name="token" type="text" required placeholder="z. B. 4ce0a9...">
                    </div>
                    <button type="submit" class="btn">Galerie öffnen</button>
                </form>
            </div>
        <?php else: ?>
            <div class="section-head reveal">
                <p class="eyebrow">
                    <?php if ($isMasterAccess): ?>
                        Master‑Zugang aktiv
                    <?php else: ?>
                        Willkommen, <?= e($access['guest_name']) ?>
                    <?php endif; ?>
                </p>
                <h1>Unsere gemeinsame Galerie</h1>
                <p>
                    <?php if ($isMasterAccess): ?>
                        Du siehst alle Bilder inkl. Status und Uploadenden.
                    <?php else: ?>
                        Hier siehst du alle Galerie-Uploads als Vorschau. Für die öffentliche Startseite werden Fotos separat freigegeben.
                    <?php endif; ?>
                </p>
                <div class="hero-actions">
                    <?php if ($access !== null || $isMasterAccess): ?>
                        <a href="upload.php" class="btn">Foto hochladen</a>
                    <?php endif; ?>
                    <a href="index.php#rsvp" class="btn btn-soft">RSVP bearbeiten</a>
                </div>
            </div>

            <?php if ($notice !== ''): ?>
                <div class="alert alert-error"><?= e($notice) ?></div>
            <?php endif; ?>

            <?php if ($approvedPhotos === []): ?>
                <div class="card">
                    <h3><?= $isMasterAccess ? 'Noch keine Bilder vorhanden' : 'Noch keine freigegebenen Fotos' ?></h3>
                    <p>Starte gerne mit dem ersten Upload.</p>
                </div>
            <?php else: ?>
                <div class="photo-grid gallery-grid reveal">
                    <?php foreach ($approvedPhotos as $photo): ?>
                        <?php $uploader = trim((string) ($photo['first_name'] ?? '') . ' ' . (string) ($photo['last_name'] ?? '')); ?>
                        <figure>
                            <img src="<?= e($photo['file_path']) ?>" alt="<?= e($photo['original_name']) ?>" loading="lazy" class="lazy">
                            <figcaption>
                                <?= e((new DateTimeImmutable($photo['uploaded_at']))->format('d.m.Y H:i')) ?>
                                <?php if ($uploader !== ''): ?> · von <?= e($uploader) ?><?php endif; ?>
                                <?php if ($isMasterAccess): ?> · Status: <?= e((string) ($photo['status'] ?? '')) ?><?php endif; ?>
                            </figcaption>
                        </figure>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>

            <section class="section">
                <div class="section-head">
                    <h2>Gästeordner (Vorschau)</h2>
                </div>
                <?php if ($guestFolders === []): ?>
                    <div class="card"><p>Noch keine Gästeordner mit Bildern vorhanden.</p></div>
                <?php else: ?>
                    <div class="grid-two reveal">
                        <?php foreach ($guestFolders as $folder): ?>
                            <article class="card">
                                <h3><?= e((string) $folder['guest_name']) ?></h3>
                                <p class="small-note"><?= e((string) $folder['count']) ?> Foto(s)</p>
                                <div class="photo-grid">
                                    <?php foreach ($folder['photos'] as $folderPhotoPath): ?>
                                        <figure>
                                            <img src="<?= e((string) $folderPhotoPath) ?>" alt="<?= e((string) $folder['guest_name']) ?>" loading="lazy" class="lazy">
                                        </figure>
                                    <?php endforeach; ?>
                                </div>
                            </article>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>
            </section>

            <?php if ($access !== null): ?>
            <section class="section">
                <div class="section-head">
                    <h2>Deine letzten Uploads</h2>
                </div>
                <div class="card">
                    <?php if ($ownUploads === []): ?>
                        <p>Du hast noch keine Fotos hochgeladen.</p>
                    <?php else: ?>
                        <table class="simple-table">
                            <thead>
                            <tr>
                                <th>Datei</th>
                                <th>Status</th>
                                <th>Hochgeladen</th>
                            </tr>
                            </thead>
                            <tbody>
                            <?php foreach ($ownUploads as $upload): ?>
                                <tr>
                                    <td><?= e($upload['original_name']) ?></td>
                                    <td><?= e($upload['status']) ?></td>
                                    <td><?= e((new DateTimeImmutable($upload['uploaded_at']))->format('d.m.Y H:i')) ?></td>
                                </tr>
                            <?php endforeach; ?>
                            </tbody>
                        </table>
                    <?php endif; ?>
                </div>
            </section>
            <?php endif; ?>
        <?php endif; ?>
    </div>
</main>

<script src="js/scripts.js"></script>
</body>
</html>
