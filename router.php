<?php
declare(strict_types=1);

// Router for PHP's built-in server (`php -S`). Prevents leaking secrets from dotfiles.
// Usage: php -S 0.0.0.0:8080 router.php

$uriPath = parse_url((string) ($_SERVER['REQUEST_URI'] ?? '/'), PHP_URL_PATH);
$path = rawurldecode(is_string($uriPath) ? $uriPath : '/');

// Normalize
if ($path === '') {
    $path = '/';
}

// Block dotfiles and common sensitive files.
$basename = basename($path);
$blockedExact = [
    '/.env',
    '/.env.example',
    '/composer.json',
    '/composer.lock',
    '/schema.sql',
    '/Dockerfile',
    '/docker-compose.yml',
];

if ($basename !== '' && str_starts_with($basename, '.')) {
    http_response_code(404);
    exit;
}

if (in_array($path, $blockedExact, true) || str_contains($path, '/.git') || str_contains($path, '/.idea')) {
    http_response_code(404);
    exit;
}

// Serve existing files directly (static assets + PHP scripts).
$fullPath = __DIR__ . $path;
if ($path !== '/' && is_file($fullPath)) {
    return false;
}

require __DIR__ . '/index.php';

