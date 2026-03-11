FROM php:8.3-apache

# Enable mod_rewrite
RUN a2enmod rewrite

# Create log and state directories
RUN mkdir -p /var/lib/wp-honeypot \
    && touch /var/log/wp-honeypot.log /var/log/wp-honeypot-intel.jsonl \
    && chown www-data:www-data /var/lib/wp-honeypot /var/log/wp-honeypot.log /var/log/wp-honeypot-intel.jsonl \
    && chmod 700 /var/lib/wp-honeypot \
    && chmod 640 /var/log/wp-honeypot.log /var/log/wp-honeypot-intel.jsonl

# Copy trap files
COPY trap/wp-trap.php /var/www/html/wp-trap.php
COPY trap/wp-trap-config.php /var/www/html/wp-trap-config.php
COPY apache/honeypot-rewrite.conf /tmp/honeypot-rewrite.conf

# Build .htaccess from rewrite rules
RUN cp /tmp/honeypot-rewrite.conf /var/www/html/.htaccess \
    && rm /tmp/honeypot-rewrite.conf

# Apache: allow .htaccess overrides
RUN sed -i '/<Directory \/var\/www\/>/,/<\/Directory>/ s/AllowOverride None/AllowOverride All/' /etc/apache2/apache2.conf

# Set ownership
RUN chown -R www-data:www-data /var/www/html

# Optional: copy dashboard
COPY tools/dashboard.php /var/www/html/dashboard/index.php
RUN chown -R www-data:www-data /var/www/html/dashboard

EXPOSE 80
