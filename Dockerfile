# syntax=docker/dockerfile:1

FROM composer:2 AS vendor
WORKDIR /app
COPY composer.json composer.lock ./
RUN composer install --no-dev --prefer-dist --no-interaction --no-progress
COPY . ./

FROM php:8.4-apache

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        libcurl4-openssl-dev \
        libpng-dev libjpeg62-turbo-dev libfreetype6-dev \
        libonig-dev \
    && docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install -j"$(nproc)" pdo_mysql curl gd mbstring \
    && rm -rf /var/lib/apt/lists/*

# Increase upload limits for the gallery uploader
RUN { \
      echo 'upload_max_filesize=20M'; \
      echo 'post_max_size=25M'; \
      echo 'max_file_uploads=50'; \
      echo 'memory_limit=256M'; \
    } > /usr/local/etc/php/conf.d/hochzeit.ini

RUN a2enmod rewrite headers

WORKDIR /var/www/html
COPY --from=vendor /app /var/www/html

# Ensure runtime dirs exist; real persistence via bind-mounts
RUN mkdir -p /var/www/html/uploads /var/www/html/qrcodes \
    && chown -R www-data:www-data /var/www/html/uploads /var/www/html/qrcodes

