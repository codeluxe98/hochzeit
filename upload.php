<?php
declare(strict_types=1);

require_once __DIR__ . '/config.php';

$theme = get_theme_settings();
$access = require_gallery_upload_access();
log_event('page_view', 'Upload-Seite aufgerufen', [
    'page' => 'upload',
    'method' => $_SERVER['REQUEST_METHOD'] ?? 'GET',
    'guest_id' => (int) ($access['guest_id'] ?? 0),
    'token_id' => (int) ($access['token_id'] ?? 0),
]);

$errors = [];
$warnings = [];
$success = [];

function process_upload_files(array $files, array $access, array &$errors, array &$warnings, array &$success): array
{
    $results = [];
    if ($files === []) {
        return $results;
    }

    $guestId = isset($access['guest_id']) ? (int) $access['guest_id'] : 0;
    $tokenId = isset($access['token_id']) ? (int) $access['token_id'] : 0;
    $guestIdParam = $guestId > 0 ? $guestId : null;
    $tokenIdParam = $tokenId > 0 ? $tokenId : null;

    $allowedMime = allowed_image_mime_types();
    $finfo = new finfo(FILEINFO_MIME_TYPE);
    $synologyTargetFolder = synology_guest_folder_path($guestId, (string) $access['guest_name']);

    foreach ($files as $file) {
        $name = (string) ($file['name'] ?? '');
        $tmpName = (string) ($file['tmp_name'] ?? '');
        $size = (int) ($file['size'] ?? 0);
        $uploadError = (int) ($file['error'] ?? UPLOAD_ERR_NO_FILE);

        if ($uploadError !== UPLOAD_ERR_OK) {
            $message = $name . ': ' . upload_error_message($uploadError);
            $errors[] = $message;
            $results[] = ['success' => false, 'file' => $name, 'message' => $message];
            log_event('upload_error', 'Uploadfehler vor Dateispeicherung', [
                'guest_id' => $guestId,
                'token_id' => $tokenId,
                'file_name' => $name,
                'upload_error' => $uploadError,
            ]);
            continue;
        }

        if ($size <= 0 || $size > UPLOAD_MAX_BYTES) {
            $message = $name . ': Datei ist leer oder größer als 15 MB.';
            $errors[] = $message;
            $results[] = ['success' => false, 'file' => $name, 'message' => $message];
            log_event('upload_error', 'Ungültige Dateigröße', [
                'guest_id' => $guestId,
                'token_id' => $tokenId,
                'file_name' => $name,
                'size' => $size,
            ]);
            continue;
        }

        $mimeType = (string) $finfo->file($tmpName);
        $extension = $allowedMime[$mimeType] ?? null;
        if ($extension === null) {
            $message = $name . ': Dateityp nicht erlaubt. Bitte nur JPG, PNG oder WEBP.';
            $errors[] = $message;
            $results[] = ['success' => false, 'file' => $name, 'message' => $message];
            log_event('upload_error', 'Nicht erlaubter Dateityp', [
                'guest_id' => $guestId,
                'token_id' => $tokenId,
                'file_name' => $name,
                'mime_type' => $mimeType,
            ]);
            continue;
        }

        $folder = date('Y/m');
        $targetDir = __DIR__ . '/uploads/' . $folder;
        if (!is_dir($targetDir)) {
            mkdir($targetDir, 0775, true);
        }

        $safeName = date('Ymd_His') . '_' . random_token(6) . '.' . $extension;
        $absolutePath = $targetDir . '/' . $safeName;
        $relativePath = 'uploads/' . $folder . '/' . $safeName;

        if (!move_uploaded_file($tmpName, $absolutePath)) {
            $message = $name . ': Datei konnte nicht gespeichert werden.';
            $errors[] = $message;
            $results[] = ['success' => false, 'file' => $name, 'message' => $message];
            log_event('upload_error', 'Datei konnte lokal nicht gespeichert werden', [
                'guest_id' => $guestId,
                'token_id' => $tokenId,
                'file_name' => $name,
            ]);
            continue;
        }

        $synologyPath = null;
        if (is_synology_configured()) {
            try {
                $synologyPath = upload_to_synology($absolutePath, $safeName, $synologyTargetFolder);
            } catch (Throwable $exception) {
                $warningMessage = $name . ': Upload zu Synology fehlgeschlagen (' . $exception->getMessage() . ').';
                $warnings[] = $warningMessage;
                log_event('synology_upload_error', 'Upload zu Synology fehlgeschlagen', [
                    'guest_id' => $guestId,
                    'token_id' => $tokenId,
                    'file_name' => $name,
                    'error' => $exception->getMessage(),
                    'target_path' => $synologyTargetFolder,
                ]);
            }
        }

        try {
            $sql = 'INSERT INTO photos (guest_id, token_id, original_name, file_path, synology_path, mime_type, size_bytes, status, uploaded_at)
                    VALUES (:guest_id, :token_id, :original_name, :file_path, :synology_path, :mime_type, :size_bytes, "pending", NOW())';
            $stmt = db()->prepare($sql);
            $stmt->execute([
                ':guest_id' => $guestIdParam,
                ':token_id' => $tokenIdParam,
                ':original_name' => $name,
                ':file_path' => $relativePath,
                ':synology_path' => $synologyPath,
                ':mime_type' => $mimeType,
                ':size_bytes' => $size,
            ]);

            $message = $name . ' wurde hochgeladen.';
            $success[] = $message;
            $results[] = ['success' => true, 'file' => $name, 'message' => $message, 'synology_path' => $synologyPath];
            log_event('upload_success', 'Foto hochgeladen', [
                'guest_id' => $guestId,
                'token_id' => $tokenId,
                'file_name' => $name,
                'mime_type' => $mimeType,
                'size' => $size,
                'synology_path' => $synologyPath,
            ]);
        } catch (Throwable $exception) {
            $message = $name . ': Metadaten konnten nicht gespeichert werden (' . $exception->getMessage() . ').';
            $errors[] = $message;
            $results[] = ['success' => false, 'file' => $name, 'message' => $message];
            log_event('upload_db_error', 'Uploadmetadaten konnten nicht gespeichert werden', [
                'guest_id' => $guestId,
                'token_id' => $tokenId,
                'file_name' => $name,
                'error' => $exception->getMessage(),
            ]);
        }
    }

    return $results;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'upload_single_ajax') {
    header('Content-Type: application/json; charset=UTF-8');

    if (!verify_csrf($_POST['csrf_token'] ?? null)) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Sicherheitsprüfung fehlgeschlagen.'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    if (!isset($_FILES['photo']) || !is_array($_FILES['photo'])) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Keine Datei übertragen.'], JSON_UNESCAPED_UNICODE);
        exit;
    }

    $singleResults = process_upload_files([$_FILES['photo']], $access, $errors, $warnings, $success);
    $result = $singleResults[0] ?? ['success' => false, 'message' => 'Unbekannter Uploadfehler.'];

    echo json_encode($result, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'upload_photos') {
    if (!verify_csrf($_POST['csrf_token'] ?? null)) {
        $errors[] = 'Sicherheitsprüfung fehlgeschlagen. Bitte erneut versuchen.';
        log_event('upload_csrf_error', 'Upload mit ungültigem CSRF-Token', [
            'guest_id' => (int) $access['guest_id'],
            'token_id' => (int) $access['token_id'],
        ]);
    } else {
        $files = normalize_uploaded_files($_FILES['photos'] ?? []);
        if ($files === []) {
            $errors[] = 'Bitte wähle mindestens ein Bild aus.';
            log_event('upload_validation_error', 'Upload ohne Dateien abgebrochen', [
                'guest_id' => (int) $access['guest_id'],
                'token_id' => (int) $access['token_id'],
            ]);
        } else {
            process_upload_files($files, $access, $errors, $warnings, $success);
        }
    }
}

$ownUploads = [];
try {
    $tokenId = (int) ($access['token_id'] ?? 0);
    if ($tokenId > 0) {
        $stmt = db()->prepare('SELECT original_name, file_path, status, uploaded_at FROM photos WHERE token_id = :token_id ORDER BY uploaded_at DESC LIMIT 50');
        $stmt->execute([':token_id' => $tokenId]);
        $ownUploads = $stmt->fetchAll();
    }
} catch (Throwable $exception) {
    $errors[] = 'Bisherige Uploads konnten nicht geladen werden: ' . $exception->getMessage();
}
?>
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Foto‑Upload · Hochzeit</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Great+Vibes&family=Nunito+Sans:wght@300;400;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="css/style.css">
    <style><?= render_theme_variables($theme) ?></style>
</head>
<body>
<header class="site-header compact-header">
    <div class="container nav-wrap">
        <a class="brand" href="gallery.php">Zur Galerie</a>
        <nav class="main-nav is-open">
            <a href="index.php">Startseite</a>
            <a href="gallery.php">Galerie</a>
        </nav>
    </div>
</header>

<main class="section">
    <div class="container grid-two">
        <section class="card reveal">
            <p class="eyebrow">Hallo <?= e($access['guest_name']) ?></p>
            <h1>Fotos hochladen</h1>
            <p>Erlaubt: JPG, PNG, WEBP bis je 15 MB. Multi‑Upload via Drag & Drop ist aktiviert. Deine Bilder sind sofort in der Galerie sichtbar; für die öffentliche Startseite erfolgt die Freigabe im Admin.</p>

            <?php foreach ($errors as $message): ?>
                <div class="alert alert-error"><?= e($message) ?></div>
            <?php endforeach; ?>

            <?php foreach ($warnings as $message): ?>
                <div class="alert alert-warn"><?= e($message) ?></div>
            <?php endforeach; ?>

            <?php foreach ($success as $message): ?>
                <div class="alert alert-success"><?= e($message) ?></div>
            <?php endforeach; ?>

            <form method="post" enctype="multipart/form-data" class="form-card" data-upload-form action="upload.php">
                <input type="hidden" name="action" value="upload_photos">
                <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">

                <div class="form-row">
                    <label for="photos">Dateien auswählen</label>
                    <div class="dropzone" data-dropzone data-input-id="photos">
                        <p class="dropzone-title">Bilder hierher ziehen</p>
                        <p class="small-note">oder klicken und mehrere Dateien auswählen</p>
                        <div class="dropzone-files" data-dropzone-files></div>
                    </div>
                    <input id="photos" name="photos[]" type="file" accept="image/jpeg,image/png,image/webp" multiple required data-drop-input>
                </div>

                <div class="upload-progress-list" data-upload-progress></div>
                <button class="btn" type="submit" data-upload-submit>Jetzt hochladen</button>
            </form>
        </section>

        <section class="card reveal">
            <h2>Deine Upload-Historie</h2>
            <?php if ($ownUploads === []): ?>
                <p>Noch keine Bilder vorhanden.</p>
            <?php else: ?>
                <table class="simple-table">
                    <thead>
                    <tr>
                        <th>Datei</th>
                        <th>Status</th>
                        <th>Zeit</th>
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
        </section>
    </div>
</main>

<script src="js/scripts.js"></script>
</body>
</html>
