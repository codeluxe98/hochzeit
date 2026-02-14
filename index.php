<?php
declare(strict_types=1);

require_once __DIR__ . '/config.php';

$theme = get_theme_settings();
$messages = [];
$frontendEnabled = frontend_is_enabled();

log_event('page_view', 'Startseite aufgerufen', [
    'page' => 'index',
    'method' => $_SERVER['REQUEST_METHOD'] ?? 'GET',
]);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';

    if ($action === 'gallery_access') {
        $tokenInputRaw = trim((string) ($_POST['token'] ?? ''));
        $target = (string) ($_POST['target'] ?? 'gallery'); // gallery | upload
        if (!in_array($target, ['gallery', 'upload'], true)) {
            $target = 'gallery';
        }

        if ($tokenInputRaw !== '') {
            if (is_gallery_master_key($tokenInputRaw)) {
                set_gallery_master_access();
                log_event('gallery_master_login', 'Master-Zugang über Index aktiviert');
                redirect($target === 'upload' ? 'upload.php' : 'gallery.php');
            }

            $tokenInput = strtolower($tokenInputRaw);
            $tokenRow = validate_gallery_token($tokenInput);
            if ($tokenRow) {
                set_gallery_access($tokenRow);
                log_event('gallery_login_success', 'Galerie-Login über Index mit Gast-Token', [
                    'guest_id' => (int) $tokenRow['guest_id'],
                    'token_id' => (int) $tokenRow['id'],
                ]);
                redirect($target === 'upload' ? 'upload.php' : 'gallery.php');
            }

            $messages[] = ['type' => 'error', 'text' => 'Token ungültig oder abgelaufen. Bitte prüfe deinen QR-Code.'];
            log_event('gallery_login_error', 'Index-Login fehlgeschlagen', [
                'token_prefix' => substr($tokenInput, 0, 8),
            ]);
        } else {
            $messages[] = ['type' => 'error', 'text' => 'Bitte gib deinen QR-Token ein.'];
            log_event('gallery_access_error', 'Galeriezugriff ohne Token versucht');
        }
    }

    if ($frontendEnabled && $action === 'rsvp') {
        if (!verify_csrf($_POST['csrf_token'] ?? null)) {
            $messages[] = ['type' => 'error', 'text' => 'Sicherheitsprüfung fehlgeschlagen. Bitte Seite neu laden.'];
            log_event('rsvp_error', 'RSVP mit ungültigem CSRF-Token');
        } else {
            $firstName = trim((string) ($_POST['first_name'] ?? ''));
            $lastName = trim((string) ($_POST['last_name'] ?? ''));
            $email = trim((string) ($_POST['email'] ?? ''));
            $phone = trim((string) ($_POST['phone'] ?? ''));
            $attending = (string) ($_POST['attending'] ?? 'yes');
            $plusOne = (int) ($_POST['plus_one'] ?? 0);
            $dietaryNotes = trim((string) ($_POST['dietary_notes'] ?? ''));
            $note = trim((string) ($_POST['note'] ?? ''));

            if ($firstName === '' || $lastName === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $messages[] = ['type' => 'error', 'text' => 'Bitte gib Vorname, Nachname und eine gültige E-Mail an.'];
                log_event('rsvp_error', 'RSVP unvollständig oder ungültig', [
                    'email' => $email,
                ]);
            } else {
                try {
                    $sql = 'INSERT INTO guests (first_name, last_name, email, phone, rsvp_status, plus_one, dietary_notes, notes, created_at)
                            VALUES (:first_name, :last_name, :email, :phone, :rsvp_status, :plus_one, :dietary_notes, :notes, NOW())
                            ON DUPLICATE KEY UPDATE
                                first_name = VALUES(first_name),
                                last_name = VALUES(last_name),
                                phone = VALUES(phone),
                                rsvp_status = VALUES(rsvp_status),
                                plus_one = VALUES(plus_one),
                                dietary_notes = VALUES(dietary_notes),
                                notes = VALUES(notes)';
                    $stmt = db()->prepare($sql);
                    $stmt->execute([
                        ':first_name' => $firstName,
                        ':last_name' => $lastName,
                        ':email' => strtolower($email),
                        ':phone' => $phone,
                        ':rsvp_status' => $attending === 'no' ? 'abgesagt' : 'zugesagt',
                        ':plus_one' => max(0, min(4, $plusOne)),
                        ':dietary_notes' => $dietaryNotes,
                        ':notes' => $note,
                    ]);

                    $messages[] = ['type' => 'success', 'text' => 'Danke dir! Deine RSVP wurde gespeichert.'];
                    log_event('rsvp_saved', 'RSVP gespeichert', [
                        'email' => strtolower($email),
                        'attending' => $attending === 'no' ? 'abgesagt' : 'zugesagt',
                        'plus_one' => max(0, min(4, $plusOne)),
                    ]);
                } catch (Throwable $exception) {
                    $messages[] = ['type' => 'error', 'text' => 'RSVP konnte nicht gespeichert werden: ' . $exception->getMessage()];
                    log_event('rsvp_error', 'RSVP Datenbankfehler', [
                        'email' => strtolower($email),
                        'error' => $exception->getMessage(),
                    ]);
                }
            }
        }
    }
}

if (!$frontendEnabled) {
    $coupleNames = trim((string) ($theme['bride_name'] ?? '') . ' & ' . (string) ($theme['groom_name'] ?? ''));
    if ($coupleNames === '&' || $coupleNames === '') {
        $coupleNames = 'Hochzeit';
    }
    ?>
    <!DOCTYPE html>
    <html lang="de">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Galerie · <?= e($coupleNames) ?></title>
        <meta name="description" content="Private QR‑Galerie. Bitte Token eingeben oder QR‑Code scannen.">
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Great+Vibes&family=Nunito+Sans:wght@300;400;600;700&display=swap" rel="stylesheet">
        <link rel="stylesheet" href="css/style.css">
        <style><?= render_theme_variables($theme) ?></style>
    </head>
    <body>
    <main class="section login-shell">
        <div class="container">
            <section class="card gate-card reveal">
                <p class="eyebrow">Private Galerie</p>
                <h1>Dein QR‑Zugang</h1>
                <p>Scanne den QR‑Code aus deiner Einladung oder gib den Token manuell ein.</p>

                <?php foreach ($messages as $message): ?>
                    <div class="alert alert-<?= e($message['type']) ?>"><?= e($message['text']) ?></div>
                <?php endforeach; ?>

                <form method="post" class="form-card narrow-form">
                    <input type="hidden" name="action" value="gallery_access">
                    <div class="form-row">
                        <label for="token">Token</label>
                        <input id="token" name="token" type="text" required placeholder="z. B. 4ce0a9...">
                    </div>
                    <div class="hero-actions" style="justify-content:flex-start">
                        <button type="submit" class="btn" name="target" value="upload">Fotos hochladen</button>
                        <button type="submit" class="btn btn-soft" name="target" value="gallery">Galerie öffnen</button>
                    </div>
                </form>
            </section>
        </div>
    </main>
    <script src="js/scripts.js"></script>
    </body>
    </html>
    <?php
    exit;
}

$previewPhotos = [];
try {
    $stmt = db()->query('SELECT file_path, original_name FROM photos WHERE status = "approved" ORDER BY uploaded_at DESC LIMIT 6');
    $previewPhotos = $stmt->fetchAll();
} catch (Throwable) {
    $previewPhotos = [];
}

$fallbackPhotos = [
    'https://images.unsplash.com/photo-1522673607200-164d1b6ce486?auto=format&fit=crop&w=1200&q=80',
    'https://images.unsplash.com/photo-1520854221256-17451cc331bf?auto=format&fit=crop&w=1200&q=80',
    'https://images.unsplash.com/photo-1519225421980-715cb0215aed?auto=format&fit=crop&w=1200&q=80',
    'https://images.unsplash.com/photo-1511285560929-80b456fea0bc?auto=format&fit=crop&w=1200&q=80',
    'https://images.unsplash.com/photo-1521747116042-5a810fda9664?auto=format&fit=crop&w=1200&q=80',
    'https://images.unsplash.com/photo-1470337458703-46ad1756a187?auto=format&fit=crop&w=1200&q=80',
];

$coupleNames = trim((string) ($theme['bride_name'] ?? 'Lena') . ' & ' . (string) ($theme['groom_name'] ?? 'Jonas'));
$weddingDateLabel = format_wedding_datetime((string) ($theme['wedding_date'] ?? '2026-08-15 14:30:00'));
$venueName = (string) ($theme['venue_name'] ?? 'Gut Sonnenhof');
$venueAddress = (string) ($theme['venue_address'] ?? 'Sonnenweg 12, 50667 Köln');
$heroImage = (string) ($theme['hero_image'] ?? '');
$storyText1 = trim((string) ($theme['story_text_1'] ?? ''));
$storyText2 = trim((string) ($theme['story_text_2'] ?? ''));
$travelTrainText = trim((string) ($theme['travel_train_text'] ?? ''));
$travelCarText = trim((string) ($theme['travel_car_text'] ?? ''));
$travelNavAddress = trim((string) ($theme['travel_nav_address'] ?? ''));
$dresscode = trim((string) ($theme['dresscode'] ?? ''));
$staysIntro = trim((string) ($theme['stays_intro'] ?? ''));
$stayOption1 = trim((string) ($theme['stay_option_1'] ?? ''));
$stayOption2 = trim((string) ($theme['stay_option_2'] ?? ''));
$stayOption3 = trim((string) ($theme['stay_option_3'] ?? ''));
$giftText1 = trim((string) ($theme['gift_text_1'] ?? ''));
$giftText2 = trim((string) ($theme['gift_text_2'] ?? ''));
$playlistText = trim((string) ($theme['playlist_text'] ?? ''));
$rsvpDeadline = trim((string) ($theme['rsvp_deadline'] ?? ''));

if ($storyText1 === '') {
    $storyText1 = 'Gestartet mit einem Espresso im Sommerregen, weitergegangen mit tausend kleinen Abenteuern. Zwischen Bahnsteigen, Sonntagsfrühstück und spontanen Roadtrips ist aus „wir schauen mal“ längst „für immer" geworden.';
}
if ($storyText2 === '') {
    $storyText2 = 'Am 15. August feiern wir diesen nächsten Schritt mit den Menschen, die uns am wichtigsten sind: euch.';
}
if ($travelTrainText === '') {
    $travelTrainText = 'Bis Köln Hbf, von dort Shuttle um 13:45 und 14:10 Uhr.';
}
if ($travelCarText === '') {
    $travelCarText = 'Vor Ort stehen ausgeschilderte Parkplätze zur Verfügung.';
}
if ($travelNavAddress === '') {
    $travelNavAddress = $venueAddress;
}
if ($dresscode === '') {
    $dresscode = 'Summer Chic';
}
if ($staysIntro === '') {
    $staysIntro = 'Wir haben Zimmerkontingente bis zum 01.07.2026 reserviert:';
}
if ($stayOption1 === '') {
    $stayOption1 = 'Hotel Gartenblick (8 Min.) – Stichwort „Lena & Jonas“';
}
if ($stayOption2 === '') {
    $stayOption2 = 'Rhein Suites (12 Min.) – Shuttle um 01:00 und 02:00 Uhr';
}
if ($stayOption3 === '') {
    $stayOption3 = 'Landhaus Bellevue (15 Min.) – ideal für Familien';
}
if ($giftText1 === '') {
    $giftText1 = 'Eure Anwesenheit ist das größte Geschenk. Wenn ihr uns zusätzlich eine Freude machen möchtet, unterstützen wir gerne unseren Flitterwochen‑Fonds für Portugal.';
}
if ($giftText2 === '') {
    $giftText2 = 'Vor Ort gibt es eine kleine Wunschbox für Karten und persönliche Nachrichten.';
}
if ($playlistText === '') {
    $playlistText = 'Schreib uns in deiner RSVP‑Nachricht deinen Lieblingssong für die Tanzfläche. Von 90s bis Disco ist alles willkommen.';
}
if ($rsvpDeadline === '') {
    $rsvpDeadline = '01.07.2026';
}

$timelineItems = [];
for ($index = 1; $index <= 4; $index++) {
    $time = trim((string) ($theme['timeline_' . $index . '_time'] ?? ''));
    $title = trim((string) ($theme['timeline_' . $index . '_title'] ?? ''));
    $text = trim((string) ($theme['timeline_' . $index . '_text'] ?? ''));

    if ($time === '' && $title === '' && $text === '') {
        continue;
    }

    $timelineItems[] = [
        'time' => $time === '' ? '--:--' : $time,
        'title' => $title === '' ? 'Programmpunkt' : $title,
        'text' => $text,
    ];
}

if ($timelineItems === []) {
    $timelineItems[] = [
        'time' => '--:--',
        'title' => 'Programmpunkt',
        'text' => 'Details folgen in Kürze.',
    ];
}
?>
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= e($coupleNames) ?> · Hochzeit</title>
    <meta name="description" content="Alle wichtigen Infos zu unserer Hochzeit: Ablauf, Anreise, RSVP und QR‑Galerie.">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Great+Vibes&family=Nunito+Sans:wght@300;400;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="css/style.css">
    <style><?= render_theme_variables($theme) ?></style>
</head>
<body>
<header class="site-header" id="top">
    <div class="container nav-wrap">
        <a class="brand" href="#top"><?= e($coupleNames) ?></a>
        <button class="menu-toggle" aria-expanded="false" aria-controls="mainNav">Menü</button>
        <nav id="mainNav" class="main-nav">
            <a href="#story">Unsere Story</a>
            <a href="#timeline">Tagesablauf</a>
            <a href="#travel">Anreise</a>
            <a href="#stays">Unterkünfte</a>
            <a href="#rsvp">RSVP</a>
            <a href="gallery.php" class="btn btn-soft">Galerie</a>
        </nav>
    </div>
</header>

<main>
    <section class="hero">
        <div class="hero-overlay"></div>
        <img src="<?= e($heroImage) ?>" alt="Verlobungsfoto des Paares" class="hero-image" loading="eager">
        <div class="container hero-content reveal">
            <p class="eyebrow">Save the Date</p>
            <h1><?= e((string) ($theme['hero_title'] ?? 'Wir sagen Ja')) ?></h1>
            <p class="hero-subtitle"><?= e($coupleNames) ?></p>
            <p class="hero-details"><?= e($weddingDateLabel) ?> · <?= e($venueName) ?></p>
            <p class="hero-note"><?= e((string) ($theme['intro_text'] ?? 'Wir freuen uns auf euch.')) ?></p>
            <div class="hero-actions">
                <a class="btn" href="#rsvp">Jetzt zusagen</a>
                <a class="btn btn-soft" href="#timeline">Programm ansehen</a>
            </div>
        </div>
    </section>

    <section class="section section-intro" id="story">
        <div class="container grid-two">
            <div class="reveal">
                <h2>Unsere Story</h2>
                <p><?= e($storyText1) ?></p>
                <p><?= e($storyText2) ?></p>
            </div>
            <aside class="card reveal">
                <h3>Der wichtigste Überblick</h3>
                <ul class="key-facts">
                    <li><strong>Datum:</strong> <?= e($weddingDateLabel) ?></li>
                    <li><strong>Location:</strong> <?= e($venueName) ?></li>
                    <li><strong>Adresse:</strong> <?= e($venueAddress) ?></li>
                    <li><strong>Dresscode:</strong> <?= e($dresscode) ?></li>
                </ul>
            </aside>
        </div>
    </section>

    <section class="section section-alt" id="timeline">
        <div class="container">
            <div class="section-head reveal">
                <p class="eyebrow">Programm</p>
                <h2>Tagesablauf</h2>
            </div>
            <div class="timeline-grid">
                <?php foreach ($timelineItems as $item): ?>
                    <article class="timeline-card reveal">
                        <span class="time"><?= e($item['time']) ?></span>
                        <h3><?= e($item['title']) ?></h3>
                        <p><?= e($item['text']) ?></p>
                    </article>
                <?php endforeach; ?>
            </div>
        </div>
    </section>

    <section class="section" id="travel">
        <div class="container grid-two">
            <article class="card reveal">
                <h2>Anreise</h2>
                <p><strong>Per Zug:</strong> <?= e($travelTrainText) ?></p>
                <p><strong>Per Auto:</strong> <?= e($travelCarText) ?></p>
                <p><strong>Adresse fürs Navi:</strong> <?= e($travelNavAddress) ?></p>
            </article>
            <article class="card reveal" id="stays">
                <h2>Unterkünfte</h2>
                <p><?= e($staysIntro) ?></p>
                <ul class="plain-list">
                    <li><?= e($stayOption1) ?></li>
                    <li><?= e($stayOption2) ?></li>
                    <li><?= e($stayOption3) ?></li>
                </ul>
            </article>
        </div>
    </section>

    <section class="section section-alt" id="registry">
        <div class="container grid-two">
            <article class="reveal">
                <h2>Geschenke</h2>
                <p><?= e($giftText1) ?></p>
                <p><?= e($giftText2) ?></p>
            </article>
            <article class="card reveal">
                <h3>Playlist‑Wunsch 🎵</h3>
                <p><?= e($playlistText) ?></p>
            </article>
        </div>
    </section>

    <section class="section" id="gallery-preview">
        <div class="container">
            <div class="section-head reveal">
                <p class="eyebrow">Erinnerungen</p>
                <h2>QR‑Galerie</h2>
                <p>Mit deinem persönlichen Token kannst du geschützte Fotos ansehen und eigene Bilder hochladen.</p>
            </div>
            <form method="post" class="token-form reveal">
                <input type="hidden" name="action" value="gallery_access">
                <label for="token">QR‑Token</label>
                <input id="token" name="token" type="text" placeholder="z. B. 3f8c..." required>
                <button class="btn" type="submit">Zur Galerie</button>
            </form>
            <div class="photo-grid reveal">
                <?php if ($previewPhotos !== []): ?>
                    <?php foreach ($previewPhotos as $photo): ?>
                        <figure>
                            <img src="<?= e($photo['file_path']) ?>" alt="<?= e($photo['original_name']) ?>" loading="lazy" class="lazy">
                        </figure>
                    <?php endforeach; ?>
                <?php else: ?>
                    <?php foreach ($fallbackPhotos as $url): ?>
                        <figure>
                            <img src="<?= e($url) ?>" alt="Hochzeitsinspiration" loading="lazy" class="lazy">
                        </figure>
                    <?php endforeach; ?>
                <?php endif; ?>
            </div>
        </div>
    </section>

    <section class="section section-alt" id="rsvp">
        <div class="container grid-two">
            <div class="reveal">
                <p class="eyebrow">Wir freuen uns auf dich</p>
                <h2>RSVP</h2>
                <p>Bitte gib uns bis spätestens <strong><?= e($rsvpDeadline) ?></strong> Bescheid, damit wir alles entspannt planen können.</p>

                <?php foreach ($messages as $message): ?>
                    <div class="alert alert-<?= e($message['type']) ?>"><?= e($message['text']) ?></div>
                <?php endforeach; ?>
            </div>

            <form method="post" class="card form-card reveal">
                <input type="hidden" name="action" value="rsvp">
                <input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">

                <div class="form-row">
                    <label for="first_name">Vorname</label>
                    <input id="first_name" name="first_name" type="text" required>
                </div>

                <div class="form-row">
                    <label for="last_name">Nachname</label>
                    <input id="last_name" name="last_name" type="text" required>
                </div>

                <div class="form-row">
                    <label for="email">E‑Mail</label>
                    <input id="email" name="email" type="email" required>
                </div>

                <div class="form-row">
                    <label for="phone">Telefon (optional)</label>
                    <input id="phone" name="phone" type="text">
                </div>

                <div class="form-row">
                    <label>Bist du dabei?</label>
                    <div class="radio-group">
                        <label><input type="radio" name="attending" value="yes" checked> Ja, ich komme</label>
                        <label><input type="radio" name="attending" value="no"> Leider nicht</label>
                    </div>
                </div>

                <div class="form-row">
                    <label for="plus_one">Zusätzliche Begleitungen</label>
                    <select id="plus_one" name="plus_one">
                        <option value="0">Keine</option>
                        <option value="1">+1</option>
                        <option value="2">+2</option>
                        <option value="3">+3</option>
                        <option value="4">+4</option>
                    </select>
                </div>

                <div class="form-row">
                    <label for="dietary_notes">Unverträglichkeiten / Essenswünsche</label>
                    <input id="dietary_notes" name="dietary_notes" type="text" placeholder="z. B. vegetarisch, glutenfrei">
                </div>

                <div class="form-row">
                    <label for="note">Nachricht an uns</label>
                    <textarea id="note" name="note" rows="4" placeholder="Dein Songwunsch oder eine liebe Nachricht"></textarea>
                </div>

                <button class="btn" type="submit">RSVP senden</button>
            </form>
        </div>
    </section>
</main>

<footer class="site-footer">
    <div class="container">
        <p><?= e($coupleNames) ?> · <?= e($weddingDateLabel) ?> · <?= e($venueName) ?></p>
        <a href="admin.php">Admin</a>
    </div>
</footer>

<script src="js/scripts.js"></script>
</body>
</html>
