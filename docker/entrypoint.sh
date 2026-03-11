#!/bin/sh
# Start php-fpm in the background, then nginx in the foreground
php-fpm -D
nginx -g 'daemon off;'
