FROM php:8.3-fpm-alpine

# Install nginx
RUN apk add --no-cache nginx

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
CMD ["/entrypoint.sh"]
