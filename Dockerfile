# Pinned to a digest for reproducible builds. Refresh on each PHP 8.3.x bump:
#   docker pull php:8.3-fpm-alpine && docker inspect --format='{{index .RepoDigests 0}}' php:8.3-fpm-alpine
FROM php:8.3-fpm-alpine@sha256:1b440e9804209491713035c4859d434f55e5cf8b0fb8c88a58f2f73d8e18b420

# Install nginx + wget (for HEALTHCHECK)
RUN apk add --no-cache nginx wget

# Create log and state directories
RUN mkdir -p /var/lib/wp-honeypot /run/nginx \
    && touch /var/log/wp-honeypot.log /var/log/wp-honeypot-intel.jsonl \
    && chown www-data:www-data /var/lib/wp-honeypot /var/log/wp-honeypot.log /var/log/wp-honeypot-intel.jsonl \
    && chmod 700 /var/lib/wp-honeypot \
    && chmod 640 /var/log/wp-honeypot.log /var/log/wp-honeypot-intel.jsonl

# Copy nginx config
COPY docker/nginx.conf /etc/nginx/http.d/default.conf

# Copy trap files
COPY trap/wp-trap.php /var/www/html/wp-trap.php
COPY trap/wp-trap-config.php /var/www/html/wp-trap-config.php

# Copy dashboard
COPY tools/dashboard.php /var/www/html/dashboard/index.php

# Set ownership
RUN chown -R www-data:www-data /var/www/html

# Entrypoint: run php-fpm + nginx
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -qO- http://127.0.0.1/health >/dev/null || exit 1
CMD ["/entrypoint.sh"]
